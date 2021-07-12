using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SignService.Services;
using SignService.Utils;

namespace SignService.SigningTools
{
    public class MageSignService : ICodeSignService
    {     
        readonly IKeyVaultService keyVaultService;
        readonly ILogger<MageSignService> logger;
        readonly ITelemetryLogger telemetryLogger;
        readonly IDirectoryUtility directoryUtility;
        readonly string magetoolPath;
        readonly string signToolName;
        readonly Lazy<ISigningToolAggregate> signToolAggregate;
        readonly ParallelOptions options = new ParallelOptions
        {
            MaxDegreeOfParallelism = 4
        };

        public MageSignService(IWebHostEnvironment hostingEnvironment,
                               IKeyVaultService keyVaultService,
                               IServiceProvider serviceProvider,
                               ILogger<MageSignService> logger,
                               ITelemetryLogger telemetryLogger,
                               IDirectoryUtility directoryUtility)
        {
            this.keyVaultService = keyVaultService;
            this.logger = logger;
            this.telemetryLogger = telemetryLogger;
            this.directoryUtility = directoryUtility;

            magetoolPath = Path.Combine(hostingEnvironment.ContentRootPath, "tools\\SDK\\x86\\mage.exe");
            signToolName = nameof(MageSignService);
            // Need to delay this as it'd create a dependency loop if directly in the ctor
            signToolAggregate = new Lazy<ISigningToolAggregate>(() => serviceProvider.GetService<ISigningToolAggregate>());
        }
        public async Task Submit(HashMode hashMode, string name, string description, string descriptionUrl, IList<string> files, string filter)
        {
            if (hashMode == HashMode.Sha1 || hashMode == HashMode.Dual)
            {
                throw new ArgumentOutOfRangeException(nameof(hashMode), "Only Sha256 is supported");
            }

            // Explicitly put this on a thread because Parallel.ForEach blocks
            await Task.Run(() => SubmitInternal(hashMode, name, description, descriptionUrl, files, filter));
        }

        public IReadOnlyCollection<string> SupportedFileExtensions { get; } = new List<string>
        {
            ".clickonce"
        };
        public bool IsDefault { get; }

        void SubmitInternal(HashMode hashMode, string name, string description, string descriptionUrl, IList<string> files, string filter)
        {
            logger.LogInformation("Signing Mage job {0} with {1} files", name, files.Count());

            var args = "-a sha256RSA";
            if (!string.IsNullOrWhiteSpace(name))
            {
                args += $@" -n ""{name}""";
            }

            var certificate = keyVaultService.GetCertificateAsync().Result;
            var timeStampUrl = keyVaultService.CertificateInfo.TimestampUrl;

            using var rsaPrivateKey = keyVaultService.ToRSA()
                                                      .Result;
            // This outer loop is for a .clickonce file            
            Parallel.ForEach(files, options, (file, state) =>
            {

                // We need to be explicit about the order these files are signed in. The data files must be signed first
                // Then the .manifest file
                // Then the nested clickonce/vsto file
                // finally the top-level clickonce/vsto file

                using var zip = new TemporaryZipFile(file, filter, logger, directoryUtility);
                // Look for the data files first - these are .deploy files
                // we need to rename them, sign, then restore the name

                var deployFilesToSign = zip.FilteredFilesInDirectory.Where(f => ".deploy".Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase))
                                                                    .ToList();

                var contentFiles = new List<string>();
                foreach (var dfile in deployFilesToSign)
                {
                        // Rename to file without extension
                        var dest = dfile.Replace(".deploy", "");
                    File.Move(dfile, dest);
                    contentFiles.Add(dest);
                }

                var filesToSign = contentFiles.ToList(); // copy it since we may add setup.exe

                var setupExe = zip.FilteredFilesInDirectory.Where(f => ".exe".Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase));
                filesToSign.AddRange(setupExe);

                // Safe to call Wait here because we're in a Parallel.ForEach()
                // sign the inner files
                signToolAggregate.Value.Submit(hashMode, name, description, descriptionUrl, filesToSign, filter).Wait();

                // rename the rest of the deploy files since signing the manifest will need them
                var deployFiles = zip.FilesExceptFiltered.Where(f => ".deploy".Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase))
                                                                 .ToList();

                foreach (var dfile in deployFiles)
                {
                    // Rename to file without extension
                    var dest = dfile.Replace(".deploy", "");
                    File.Move(dfile, dest);
                    contentFiles.Add(dest);
                }

                // at this point contentFiles has all deploy files renamed

                // Inner files are now signed
                // now look for the manifest file and sign that

                var manifestFile = zip.FilteredFilesInDirectory.Single(f => ".manifest".Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase));

                var fileArgs = $@"-update ""{manifestFile}"" {args}";

                telemetryLogger.OnSignFile(manifestFile, signToolName);
                if (!Sign(fileArgs, manifestFile, hashMode, rsaPrivateKey, certificate, timeStampUrl))
                {
                    throw new Exception($"Could not sign {manifestFile}");
                }

                // Read the publisher name from the manifest for use below
                var manifestDoc = XDocument.Load(manifestFile);
                var ns = manifestDoc.Root.GetDefaultNamespace();
                var publisherEle = manifestDoc.Root.Element(ns + "publisherIdentity");
                var pubName = publisherEle.Attribute("name").Value;

                var publisherParam = "";

                var dict = DistinguishedNameParser.Parse(pubName);
                if (dict.TryGetValue("CN", out var cns))
                {
                        // get the CN. it may be quoted
                        publisherParam = $@"-pub ""{string.Join("+", cns.Select(s => s.Replace("\"", "")))}"" ";
                }

                // Now sign the inner vsto/clickonce file
                // Order by desending length to put the inner one first
                var clickOnceFilesToSign = zip.FilteredFilesInDirectory
                                                .Where(f => ".vsto".Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase) ||
                                                            ".application".Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase))
                                                .Select(f => new { file = f, f.Length })
                                                .OrderByDescending(f => f.Length)
                                                .Select(f => f.file)
                                                .ToList();

                foreach (var f in clickOnceFilesToSign)
                {
                    fileArgs = $@"-update ""{f}"" {args} -appm ""{manifestFile}"" {publisherParam}";
                    if (!string.IsNullOrWhiteSpace(descriptionUrl))
                    {
                        fileArgs += $@" -SupportURL {descriptionUrl}";
                    }

                    telemetryLogger.OnSignFile(f, signToolName);
                    if (!Sign(fileArgs, f, hashMode, rsaPrivateKey, certificate, timeStampUrl))
                    {
                        throw new Exception($"Could not sign {f}");
                    }
                }

                // restore the deploy files
                foreach (var dfile in contentFiles)
                {
                    File.Move(dfile, $"{dfile}.deploy");
                }

                zip.Save();
            });
        }

        // Inspired from https://github.com/squaredup/bettersigntool/blob/master/bettersigntool/bettersigntool/SignCommand.cs

        bool Sign(string args, string inputFile, HashMode hashMode, RSA rsaPrivateKey, X509Certificate2 publicCertificate, string timestampUrl)
        {
            var retry = TimeSpan.FromSeconds(5);
            var attempt = 1;
            do
            {
                if (attempt > 1)
                {
                    logger.LogInformation($"Performing attempt #{attempt} of 3 attempts after {retry.TotalSeconds}s");
                    Thread.Sleep(retry);
                    retry = TimeSpan.FromSeconds(Math.Pow(retry.TotalSeconds, 1.5));
                }

                if (RunSignTool(args, inputFile, hashMode, rsaPrivateKey, publicCertificate, timestampUrl))
                {
                    logger.LogInformation($"Signed successfully");
                    return true;
                }

                attempt++;

            } while (attempt <= 3);

            logger.LogError($"Failed to sign. Attempts exceeded");

            return false;
        }

        bool RunSignTool(string args, string inputFile, HashMode hashMode, RSA rsaPrivateKey, X509Certificate2 publicCertificate, string timestampUrl)
        {
            // Append a sha256 signature
            using var signtool = new Process
            {
                StartInfo =
                {
                    FileName = magetoolPath,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    Arguments = args
                }
            };
            var startTime = DateTimeOffset.UtcNow;
            var stopwatch = Stopwatch.StartNew();
            logger.LogInformation("Signing {fileName}", signtool.StartInfo.FileName);
            signtool.Start();

            var output = signtool.StandardOutput.ReadToEnd();
            var error = signtool.StandardError.ReadToEnd();
            logger.LogInformation("Mage Out {MageOutput}", output);

            if (!string.IsNullOrWhiteSpace(error))
            {
                logger.LogInformation("Mage Err {MageError}", error);
            }

            if (!signtool.WaitForExit(30 * 1000))
            {
                logger.LogError("Error: Mage took too long to respond {exitCode}", signtool.ExitCode);
                try
                {
                    signtool.Kill();
                }
                catch (Exception ex)
                {
                    throw new Exception("Mage timed out and could not be killed", ex);
                }

                logger.LogError("Error: Mage took too long to respond {exitCode}", signtool.ExitCode);
                throw new Exception($"Mage took too long to respond");
            }

            if (signtool.ExitCode == 0)
            {
                // Now add the signature 
                ManifestSigner.SignFile(inputFile, hashMode, rsaPrivateKey, publicCertificate, timestampUrl);

                telemetryLogger.TrackSignToolDependency(signToolName, inputFile, startTime, stopwatch.Elapsed, null, signtool.ExitCode);

                return true;
            }

            telemetryLogger.TrackSignToolDependency(signToolName, inputFile, startTime, stopwatch.Elapsed, null, signtool.ExitCode);

            logger.LogError("Error: Signtool returned {exitCode}", signtool.ExitCode);

            return false;

        }
    }
}
