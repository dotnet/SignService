﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SignService.SigningTools
{
    public class VsixSignService : ICodeSignService
    {
        readonly ILogger<VsixSignService> logger;
        readonly string signtoolPath;
        readonly string timeStampUrl;
        readonly string thumbprint;

        readonly ParallelOptions options = new ParallelOptions
        {
            MaxDegreeOfParallelism = 4
        };

        public VsixSignService(IOptionsSnapshot<CertificateInfo> certificationInfo, IHostingEnvironment hostingEnvironment, ILogger<VsixSignService> logger)
        {
            timeStampUrl = certificationInfo.Value.TimestampUrl;
            thumbprint = certificationInfo.Value.Thumbprint;
            this.logger = logger;
            signtoolPath = Path.Combine(hostingEnvironment.ContentRootPath, "tools\\OpenVsixSignTool\\OpenVsixSignTool.exe");
        }
        public Task Submit(HashMode hashMode, string name, string description, string descriptionUrl, IList<string> files)
        {
            // TODO: crack open the VISX and pass the contents to the aggregator
            // if(aggregate == null) aggregate = serviceProvider.GetService<ISigningToolAggregate>();

            // Explicitly put this on a thread because Parallel.ForEach blocks
            return Task.Run(() => SubmitInternal(hashMode, name, description, descriptionUrl, files));
        }

        public IReadOnlyCollection<string> SupportedFileExtensions { get; } = new List<string>
        {
            ".vsix"
        };
        public bool IsDefault { get; }

        void SubmitInternal(HashMode hashMode, string name, string description, string descriptionUrl, IList<string> files)
        {
            logger.LogInformation("Signing OpenVsixSignTool job {0} with {1} files", name, files.Count());

            Parallel.ForEach(files, options, (file, state) =>
                                             {
                                                 // Dual isn't supported, use sha256
                                                 var alg = hashMode == HashMode.Sha1 ? "sha1" : "sha256";

                                                 var args = $@"sign --sha1 {thumbprint} --timestamp {timeStampUrl} -ta {alg} -fd {alg} ""{file}""";


                                                 if (!Sign(args))
                                                 {
                                                     throw new Exception($"Could not sign {file}");
                                                 }
                                             });
        }

        // Inspired from https://github.com/squaredup/bettersigntool/blob/master/bettersigntool/bettersigntool/SignCommand.cs

        bool Sign(string args)
        {
            var retry = TimeSpan.FromSeconds(5);
            var attempt = 1;
            do
            {
                if (attempt > 1)
                {
                    logger.LogInformation($"Performing attempt #{attempt} of 3 attempts after {retry.TotalSeconds}s");
                    Thread.Sleep(retry);
                }

                if (RunSignTool(args))
                {
                    logger.LogInformation($"Signed {args}");
                    return true;
                }

                attempt++;

                retry = TimeSpan.FromSeconds(Math.Pow(retry.TotalSeconds, 1.5));

            } while (attempt <= 3);

            logger.LogError($"Failed to sign {args}. Attempts exceeded");

            return false;
        }

        bool RunSignTool(string args)
        {
            // Append a sha256 signature
            using (var signtool = new Process
            {
                StartInfo =
                {
                    FileName = signtoolPath,
                    UseShellExecute = false,
                    RedirectStandardError = false,
                    RedirectStandardOutput = false,
                    Arguments = args
                }
            })
            {
                logger.LogInformation(@"""{0}"" {1}", signtool.StartInfo.FileName, signtool.StartInfo.Arguments);
                signtool.Start();
                if (!signtool.WaitForExit(30 * 1000))
                {
                    logger.LogError("Error: OpenVsixSignTool took too long to respond {0}", signtool.ExitCode);
                    try
                    {
                        signtool.Kill();
                    }
                    catch (Exception ex)
                    {
                        throw new Exception("OpenVsixSignTool timed out and could not be killed", ex);
                    }

                    logger.LogError("Error: OpenVsixSignTool took too long to respond {0}", signtool.ExitCode);
                    throw new Exception($"OpenVsixSignTool took too long to respond with {signtool.StartInfo.Arguments}");
                }

                if (signtool.ExitCode == 0)
                {
                    return true;
                }

                logger.LogError("Error: Signtool returned {0}", signtool.ExitCode);

                return false;
            }

        }
    }
}
