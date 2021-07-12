using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;

using Newtonsoft.Json;
using SignService.Models;

namespace SignService.Services
{
    public interface IUserAdminService
    {
        Task<(GraphUser, string)> CreateUserAsync(string displayName, string username, bool configured, Uri keyVaultUrl, string keyVaultCertName, string timestampUrl);
        Task UpdateUserAsync(Guid objectId, string displayName, bool? configured, Uri keyVaultUrl, string keyVaultCertName, string timestampUrl);
        Task<IEnumerable<GraphUser>> GetUsersAsync(string displayName);
        Task<GraphUser> GetUserByObjectIdAsync(Guid objectId);
        Task<string> UpdatePasswordAsync(Guid objectId);
        Task<IEnumerable<GraphUser>> GetSignServiceUsersAsync();
        Task RegisterExtensionPropertiesAsync();
        Task UnRegisterExtensionPropertiesAsync();
    }

    public class UserAdminService : IUserAdminService
    {
        readonly MicrosoftIdentityOptions azureAdOptions;
        readonly IApplicationConfiguration applicationConfiguration;
        readonly IGraphHttpService graphHttpService;
        readonly string extensionPrefix;

        public UserAdminService(IOptionsSnapshot<MicrosoftIdentityOptions> azureAdOptions, IApplicationConfiguration applicationConfiguration, IGraphHttpService graphHttpService)
        {
            this.azureAdOptions = azureAdOptions.Get(OpenIdConnectDefaults.AuthenticationScheme);
            this.applicationConfiguration = applicationConfiguration;
            this.graphHttpService = graphHttpService;
            extensionPrefix = $"extension_{this.azureAdOptions.ClientId.Replace("-", "")}_";
        }

        public async Task RegisterExtensionPropertiesAsync()
        {
            var extensionProperties = new[]
            {
                new ExtensionProperty
                {
                    DataType = "Boolean",
                    Name = "signServiceConfigured",
                    TargetObjects = new[]
                    {
                        "User"
                    }
                },
                new ExtensionProperty
                {
                    DataType = "String",
                    Name = "keyVaultUrl",
                    TargetObjects = new[]
                    {
                        "User"
                    }
                },
                new ExtensionProperty
                {
                    DataType = "String",
                    Name = "timestampUrl",
                    TargetObjects = new[]
                    {
                        "User"
                    }
                },
                new ExtensionProperty
                {
                    DataType = "String",
                    Name = "keyVaultCertificateName",
                    TargetObjects = new[]
                    {
                        "User"
                    }
                }
            };

            // Get current properties
            var uri = $"/applications/{applicationConfiguration.ApplicationObjectId}/extensionProperties?api-version=1.6";

            var appExts = await graphHttpService.Get<ExtensionProperty>(uri).ConfigureAwait(false);

            foreach (var prop in extensionProperties)
            {
                // Only add it if it doesn't exist already
                if (appExts.FirstOrDefault(ep => ep.Name.EndsWith(prop.Name)) == null)
                {
                    var c = await graphHttpService.Post<ExtensionProperty, ExtensionProperty>($"/applications/{applicationConfiguration.ApplicationObjectId}/extensionProperties?api-version=1.6",
                                                                                              prop,
                                                                                              accessAsUser: true)
                                                  .ConfigureAwait(false);
                }
            }

            var appId = azureAdOptions.ClientId.Replace("-", "");

            // Set optional claims since we want these extension attributes to be included in the access token
            var optionalClaims = new OptionalClaims
            {
                accessToken = (from ep in extensionProperties
                               select new ClaimInformation
                               {
                                   name = $"extension_{appId}_{ep.Name}",
                                   source = "user",
                                   essential = true
                               }).ToArray()
            };

            await SetOptionalClaims(optionalClaims, applicationConfiguration.ApplicationObjectId);
        }

        public async Task UnRegisterExtensionPropertiesAsync()
        {
            var uri = $"/applications/{applicationConfiguration.ApplicationObjectId}/extensionProperties?api-version=1.6";

            var result = await graphHttpService.Get<ExtensionProperty>(uri).ConfigureAwait(false);

            foreach (var prop in result)
            {
                await graphHttpService.Delete($"/applications/{applicationConfiguration.ApplicationObjectId}/extensionProperties/{prop.ObjectId}?api-version=1.6",
                                              accessAsUser: true)
                                      .ConfigureAwait(false);
            }
        }

        public async Task<IEnumerable<GraphUser>> GetUsersAsync(string displayName)
        {
            displayName = displayName.Replace("'", ""); // don't unescape

            var uri = $"/users?api-version=1.6&$filter=startswith(displayName, '{displayName}') or startswith(givenName, '{displayName}') or startswith(surname, '{displayName}')";

            var result = await graphHttpService.Get<GraphUser>(uri).ConfigureAwait(false);

            return result;
        }

        public async Task<GraphUser> GetUserByObjectIdAsync(Guid objectId)
        {
            var uri = $"/users/{objectId}?api-version=1.6";

            var result = await graphHttpService.GetScalar<GraphUser>(uri).ConfigureAwait(false);

            return result;
        }


        public async Task<(GraphUser, string)> CreateUserAsync(string displayName, string username, bool configured, Uri keyVaultUrl, string keyVaultCertName, string timestampUrl)
        {
            var uri = $"/users?api-version=1.6";

            // validate the args are present
            if (string.IsNullOrWhiteSpace(displayName))
            {
                throw new ArgumentException("Argument cannot be blank", nameof(displayName));
            }

            if (string.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentException("Argument cannot be blank", nameof(username));
            }

            if (configured)
            {
                if (keyVaultUrl == null)
                {
                    throw new ArgumentException("Argument cannot be blank when configured is true", nameof(keyVaultUrl));
                }

                if (string.IsNullOrWhiteSpace(keyVaultCertName))
                {
                    throw new ArgumentException("Argument cannot be blank when configured is true", nameof(keyVaultCertName));
                }

                if (string.IsNullOrWhiteSpace(timestampUrl))
                {
                    throw new ArgumentException("Argument cannot be blank when configured is true", nameof(timestampUrl));
                }
            }

            var password = GetRandomPassword();

            // if username doesn't contain an @, use the default domain
            if (!username.Contains("@"))
            {
                username += $"@{applicationConfiguration.PrimaryDomain}";
            }

            var user = new GraphUser
            {
                DisplayName = displayName,
                UserPrincipalName = username,
                UserType = "Guest", // we create this account as a guest to limit overall privs in the directory (enumeration of users, etc)
                KeyVaultUrl = keyVaultUrl,
                KeyVaultCertificateName = string.IsNullOrWhiteSpace(keyVaultCertName) ? null : keyVaultCertName,
                TimestampUrl = string.IsNullOrWhiteSpace(timestampUrl) ? null : timestampUrl,
                SignServiceConfigured = configured,
                AccountEnabled = true,
                MailNickname = username.Substring(0, username.IndexOf('@')), // use the username up to the @
                PasswordProfile = new PasswordProfile
                {
                    ForceChangePasswordNextLogin = false,
                    Password = password
                },
                PasswordPolicies = "DisablePasswordExpiration, DisableStrongPassword"
            };


            var result = await graphHttpService.Post<GraphUser, GraphUser>(uri, user).ConfigureAwait(false);

            return (result, password);
        }

        public async Task<string> UpdatePasswordAsync(Guid objectId)
        {
            // Update the password on the account. For safety, we'll make sure this account is configured as a SignService Account first

            var user = await GetUserByObjectIdAsync(objectId).ConfigureAwait(false);
            var uri = $"/users/{user.ObjectId}?api-version=1.6";
            var password = GetRandomPassword();

            if (user.SignServiceConfigured != null)
            {
                // new user so we don't touch existing values
                var toUpdate = new GraphUser
                {
                    ObjectId = user.ObjectId,
                    PasswordProfile = new PasswordProfile
                    {
                        ForceChangePasswordNextLogin = false,
                        Password = password
                    }
                };

                await graphHttpService.Patch(uri, toUpdate, accessAsUser: true).ConfigureAwait(false);
                return password;
            }
            else
            {
                throw new InvalidOperationException("Can only update password of SignServiceConfigured users");
            }
        }

        public async Task UpdateUserAsync(Guid objectId, string displayName, bool? configured, Uri keyVaultUrl, string keyVaultCertName, string timestampUrl)
        {
            var uri = $"/users/{objectId}?api-version=1.6";

            // We never want to set DisplayName to blank
            if (string.IsNullOrWhiteSpace(displayName))
            {
                throw new ArgumentException("Argument cannot be blank when configured is true", nameof(displayName));
            }

            if (configured == true)
            {
                // validate the args are present
                if (keyVaultUrl == null)
                {
                    throw new ArgumentException("Argument cannot be blank when configured is true", nameof(keyVaultUrl));
                }

                if (string.IsNullOrWhiteSpace(keyVaultCertName))
                {
                    throw new ArgumentException("Argument cannot be blank when configured is true", nameof(keyVaultCertName));
                }

                if (string.IsNullOrWhiteSpace(timestampUrl))
                {
                    throw new ArgumentException("Argument cannot be blank when configured is true", nameof(timestampUrl));
                }
            }

            var user = new GraphUserUpdate
            {
                ObjectId = objectId,
                DisplayName = displayName,
                SignServiceConfigured = configured,
                KeyVaultUrl = keyVaultUrl,
                KeyVaultCertificateName = string.IsNullOrWhiteSpace(keyVaultCertName) ? null : keyVaultCertName,
                TimestampUrl = string.IsNullOrWhiteSpace(timestampUrl) ? null : timestampUrl
            };

            await graphHttpService.Patch(uri, user).ConfigureAwait(false);
        }

        public async Task<IEnumerable<GraphUser>> GetSignServiceUsersAsync()
        {
            // This may throw if we run this query before the extension is registered. Just return empty
            try
            {
                var uri = $"/users?api-version=1.6&$filter={extensionPrefix}signServiceConfigured eq true or {extensionPrefix}signServiceConfigured eq false";

                var result = await graphHttpService.Get<GraphUser>(uri).ConfigureAwait(false);

                return result;
            }
            catch (Exception)
            {
                return Enumerable.Empty<GraphUser>();
            }
        }

        async Task SetOptionalClaims(OptionalClaims claims, string objectId)
        {

            var jsonstring = JsonConvert.SerializeObject(claims);

            var payload = $"{{\"optionalClaims\":{jsonstring}}}";

            await graphHttpService.Patch($"/applications/{objectId}?api-version=1.6", payload, true);
        }

        static string GetRandomPassword()
        {
            const string ALLOWED_CHARS = @"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@#$%^&*-_!+=[]{}|\:,.?/~();";
            const int PASSWORD_LENGTH = 64; // AAD has a max of 256 char passwords
            Span<char> builder = stackalloc char[PASSWORD_LENGTH];
            for (var i = 0; i < PASSWORD_LENGTH; i++)
            {
                builder[i] = ALLOWED_CHARS[RandomNumberGenerator.GetInt32(0, ALLOWED_CHARS.Length)];
            }

            return new string(builder);
        }

#pragma warning disable IDE1006 // Naming Styles
        class OptionalClaims
        {
            public ClaimInformation[] accessToken { get; set; }
        }

        class ClaimInformation
        {
            public string name { get; set; }
            public string source { get; set; }
            public bool essential { get; set; }
        }
#pragma warning restore IDE1006 // Naming Styles
    }
}
