﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.CommandLineUtils;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json.Linq;
using Refit;

namespace SignClient
{
    class SignCommand
    {
        readonly CommandLineApplication signCommandLineApplication;

        static class EXIT_CODES
        {
            public const int SUCCESS = 0;
            public const int INVALID_OPTIONS = 1;
            public const int FAILED = 2;
        }

        public SignCommand(CommandLineApplication signCommandLineApplication)
        {
            this.signCommandLineApplication = signCommandLineApplication;
        }

        public async Task<int> SignAsync
        (
            CommandOption configFile,
            CommandOption inputFile,
            CommandOption outputFile,
            CommandOption fileList,
            CommandOption clientSecret,
            CommandOption username,
            CommandOption name,
            CommandOption description,
            CommandOption descriptionUrl
        )
        {
            try
            {
                // verify required parameters
                if (!configFile.HasValue())
                {
                    signCommandLineApplication.Error.WriteLine("--config parameter is required");
                    return EXIT_CODES.INVALID_OPTIONS;
                }

                if (!inputFile.HasValue())
                {
                    signCommandLineApplication.Error.WriteLine("--input parameter is required");
                    return EXIT_CODES.INVALID_OPTIONS;
                }

                if (!name.HasValue())
                {
                    signCommandLineApplication.Error.WriteLine("--name parameter is required");
                    return EXIT_CODES.INVALID_OPTIONS;
                }

                if (!outputFile.HasValue())
                {
                    // use input as the output value
                    outputFile.Values.Add(inputFile.Value());
                }

                var builder = new ConfigurationBuilder()
                              .AddJsonFile(ExpandFilePath(configFile.Value()))
                              .AddEnvironmentVariables();

                var configuration = builder.Build();

                // Setup Refit
                var settings = new RefitSettings
                {
                    AuthorizationHeaderValueGetter = async () =>
                    {
                        var authority = $"{configuration["SignClient:AzureAd:AADInstance"]}{configuration["SignClient:AzureAd:TenantId"]}";

                        var clientId = configuration["SignClient:AzureAd:ClientId"];
                        var resourceId = configuration["SignClient:Service:ResourceId"];

                        // See if we have a Username option
                        if (username.HasValue())
                        {
                            // ROPC flow
                            // Cannot use ADAL since there's no support for ROPC in .NET Core
                            var parameters = new Dictionary<string, string>
                            {
                                {"resource", resourceId },
                                {"client_id", clientId },
                                {"grant_type", "password" },
                                {"username", username.Value() },
                                {"password", clientSecret.Value() },
                            };
                            using (var adalClient = new HttpClient())
                            {
                                var result = await adalClient.PostAsync($"{authority}/oauth2/token", new FormUrlEncodedContent(parameters));

                                var res = await result.Content.ReadAsStringAsync();
                                result.EnsureSuccessStatusCode();

                                var jObj = JObject.Parse(res);
                                var token = jObj["access_token"].Value<string>();
                                return token;
                            }
                        }
                        else
                        {
                            // Client credential flow
                            var context = new AuthenticationContext(authority);
                            var res = await context.AcquireTokenAsync(resourceId, new ClientCredential(clientId, clientSecret.Value()));
                            return res.AccessToken;
                        }
                    }
                };

                var client = RestService.For<ISignService>(configuration["SignClient:Service:Url"], settings);

                // Prepare input/output file
                var input = new FileInfo(ExpandFilePath(inputFile.Value()));
                var output = new FileInfo(ExpandFilePath(outputFile.Value()));
                Directory.CreateDirectory(output.DirectoryName);
                
                // Do action

                HttpResponseMessage response;
                
                response = await client.SignFile(input, fileList.HasValue() ? new FileInfo(ExpandFilePath(fileList.Value())) : null, HashMode.Sha256, name.Value(), description.Value(), description.Value());
                
                // Check response

                if (!response.IsSuccessStatusCode)
                {
                    Console.Error.WriteLine($"Server returned non Ok response: {(int)response.StatusCode} {response.ReasonPhrase}");
                    return -1;
                }

                var str = await response.Content.ReadAsStreamAsync();

                using (var fs = output.OpenWrite())
                {
                    await str.CopyToAsync(fs);
                }
            }
            catch (Exception e)
            {
                signCommandLineApplication.Error.WriteLine("Exception: " + e);
                return EXIT_CODES.FAILED;
            }

            return EXIT_CODES.SUCCESS;
        }

        static string ExpandFilePath(string file)
        {
            if (!Path.IsPathRooted(file))
            {
                return $"{Environment.CurrentDirectory}{Path.DirectorySeparatorChar}{file}";
            }
            return file;
        }
    }
}
