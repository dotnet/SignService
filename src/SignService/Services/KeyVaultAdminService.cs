using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Management.KeyVault;
using Microsoft.Azure.Management.KeyVault.Models;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;
//using Microsoft.IdentityModel.Clients.ActiveDirectory;
using SignService.Models;
using SignService.Utils;

namespace SignService.Services
{
    public interface IKeyVaultAdminService
    {
        Task<VaultModel> CreateVaultForUserAsync(string objectId, string upn, string displayName);
        Task<VaultModel> GetVaultAsync(string vaultName);
        Task<List<VaultModel>> ListKeyVaultsAsync();
        Task<List<CertificateModel>> GetCertificatesInVaultAsync(Uri vaultUri);
        Task<DeleteCertificateOperation> CancelCsrAsync(string vaultName, string certificateName);
        Task<KeyVaultCertificateWithPolicy> MergeCertificate(string vaultName, string certificateName, byte[] certData);
        Task<CertificateOperation> GetCertificateOperation(Uri vaultUrl, string certificateName);
        Task<CertificateOperation> CreateCsrAsync(string vaultName, string certificateName, string commonName);
    }

    public class KeyVaultAdminService : IKeyVaultAdminService
    {
        //readonly AuthenticationContext adalContext;
        readonly string resourceGroup;
        readonly MicrosoftIdentityOptions azureAdOptions;
        readonly AdminConfig adminConfig;
        readonly Guid tenantId;
        readonly Guid clientId;
        readonly string userId;
        readonly KeyVaultManagementClient kvManagmentClient;
        readonly TokenCredential appTokenCredential;
        readonly IGraphHttpService graphHttpService;
        readonly IApplicationConfiguration applicationConfiguration;
        readonly ResourceIds resources;
        readonly ITokenAcquisition tokenAcquisition;

        public KeyVaultAdminService(IOptionsSnapshot<MicrosoftIdentityOptions> azureAdOptions,
                                    IOptionsSnapshot<AdminConfig> adminConfig,
                                    IOptionsSnapshot<ResourceIds> resources,
                                    IGraphHttpService graphHttpService,
                                    IApplicationConfiguration applicationConfiguration,
                                    IUser user,
                                    ITokenAcquisition tokenAcquisition)
            //,
              //                      IHttpContextAccessor contextAccessor)
        {
            userId = user.ObjectId;
            tenantId = Guid.Parse(user.TenantId);
            this.tokenAcquisition = tokenAcquisition;
            this.azureAdOptions = azureAdOptions.Get(OpenIdConnectDefaults.AuthenticationScheme);

            clientId = Guid.Parse(this.azureAdOptions.ClientId);

            //adalContext = new AuthenticationContext($"{this.azureAdOptions.Instance}{this.azureAdOptions.TenantId}", new ADALSessionCache(userId, contextAccessor));
            resourceGroup = adminConfig.Value.ResourceGroup;

            kvManagmentClient = new KeyVaultManagementClient(new AutoRestCredential<KeyVaultManagementClient>(GetAppToken))
            {
                SubscriptionId = adminConfig.Value.SubscriptionId,
                BaseUri = new Uri(adminConfig.Value.ArmInstance)

            };

            appTokenCredential = new ClientSecretCredential(this.azureAdOptions.TenantId, this.azureAdOptions.ClientId, this.azureAdOptions.ClientSecret);

            
            this.adminConfig = adminConfig.Value;
            this.graphHttpService = graphHttpService;
            this.applicationConfiguration = applicationConfiguration;
            this.resources = resources.Value;
        }

        async Task<string> GetAppToken(string authority, string resource, string scope)
        {
            //var result = await adalContext.AcquireTokenAsync(resources.AzureRM, new ClientCredential(azureAdOptions.ClientId, azureAdOptions.ClientSecret)).ConfigureAwait(false);

            var token = await tokenAcquisition.GetAccessTokenForAppAsync(resources.AzureRMAppId).ConfigureAwait(false);
            return token;
            //return result.AccessToken;
        }

        async Task<string> GetOboToken(string authority, string resource, string scope)
        {
            //   var result = await adalContext.AcquireTokenSilentAsync(resources.AzureRM, new ClientCredential(azureAdOptions.ClientId, azureAdOptions.ClientSecret), UserIdentifier.AnyUser).ConfigureAwait(false);

            // return result.AccessToken;            

            var token = await tokenAcquisition.GetAccessTokenForUserAsync(new[] { resources.AzureRMUserId }).ConfigureAwait(false);
            return token;
        }

        public async Task<List<VaultModel>> ListKeyVaultsAsync()
        {
            var totalVaults = new List<Vault>();
            var vaults = await kvManagmentClient.Vaults.ListByResourceGroupAsync(resourceGroup)
                                       .ConfigureAwait(false);

            totalVaults.AddRange(vaults);
            var nextLink = vaults.NextPageLink;

            // Get the rest if there's more
            while (!string.IsNullOrWhiteSpace(nextLink))
            {
                vaults = await kvManagmentClient.Vaults.ListByResourceGroupNextAsync(nextLink)
                                       .ConfigureAwait(false);
                totalVaults.AddRange(vaults);
                nextLink = vaults.NextPageLink;
            }

            return totalVaults.Select(ToVaultModel).ToList();
        }

        public async Task<VaultModel> GetVaultAsync(string vaultName)
        {
            var vault = await kvManagmentClient.Vaults.GetAsync(resourceGroup, vaultName).ConfigureAwait(false);

            return ToVaultModel(vault);
        }

        public async Task<VaultModel> CreateVaultForUserAsync(string objectId, string upn, string displayName)
        {
            // Get the service principal id for this application since we'll need it
            var spId = await graphHttpService.GetValue<string>($"/servicePrincipalsByAppId/{azureAdOptions.ClientId}/objectId?api-version=1.6");

            var parameters = new VaultCreateOrUpdateParameters()
            {
                Location = applicationConfiguration.Location,
                Properties = new VaultProperties()
                {
                    TenantId = tenantId,
                    Sku = new Sku(SkuName.Premium),
                    AccessPolicies = new List<AccessPolicyEntry>
                    {
                        // Grant this application admin permissions on the management plane to deal with keys and certificates
                        new AccessPolicyEntry
                        {
                          ObjectId = spId,
                          TenantId = tenantId,
                          Permissions  = new Permissions
                          {
                              Keys = new List<string>
                              {
                                  "Backup",
                                  "Create",
                                  "Delete",
                                  "Get",
                                  "Import",
                                  "List",
                                  "Restore",
                                  "Update",
                                  "Recover"
                              },
                              Certificates = new List<string>
                              {
                                  "Get",
                                  "List",
                                  "Update",
                                  "Create",
                                  "Import",
                                  "Delete",
                                  "ManageContacts",
                                  "ManageIssuers",
                                  "GetIssuers",
                                  "ListIssuers",
                                  "SetIssuers",
                                  "DeleteIssuers",
                                  "Backup",
                                  "Restore",
                                  "Recover"
                              }
                          }
                        },

                        // Grant the current user the management plane access for use in the portal/powershell for 
                        // manual tasks
                        new AccessPolicyEntry
                        {
                            ObjectId = userId,
                            TenantId = tenantId,
                            Permissions  = new Permissions
                            {
                                Keys = new List<string>
                                {
                                    "Backup",
                                    "Create",
                                    "Delete",
                                    "Get",
                                    "Import",
                                    "List",
                                    "Restore",
                                    "Update",
                                    "Recover"
                                },
                                Certificates = new List<string>
                                {
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "ManageContacts",
                                    "ManageIssuers",
                                    "GetIssuers",
                                    "ListIssuers",
                                    "SetIssuers",
                                    "DeleteIssuers",
                                    "Backup",
                                    "Restore",
                                    "Recover"
                                }
                            }
                        },

                        // Needs Keys: Get + Sign, Certificates: Get
                        new AccessPolicyEntry
                        {
                            TenantId = tenantId,
                            ObjectId = objectId,
                            ApplicationId = clientId,
                            Permissions  = new Permissions
                            {
                                Keys = new List<string>
                                {
                                    "Get",
                                    "Sign",
                                },
                                Certificates = new List<string>
                                {
                                    "Get"
                                }
                            }
                        }
                    }
                },
                Tags = new Dictionary<string, string>
                {
                    {"userName", upn },
                    {"displayName", displayName }
                },
            };

            // for the vault name, we get up to 24 characters, so use the following:
            // upn up to the @ then a dash then fill with a guid truncated
            var vaultName = $"{upn.Substring(0, upn.IndexOf('@'))}-{Guid.NewGuid():N}";

            // Truncate to 24 chars
            vaultName = vaultName.Substring(0, 24);

            // Create uses an OBO so that this only works if the user has contributer+ access to the resource group
            using var client = new KeyVaultManagementClient(new AutoRestCredential<KeyVaultManagementClient>(GetOboToken))
            {
                SubscriptionId = adminConfig.SubscriptionId
            };
            var vault = await client.Vaults.CreateOrUpdateAsync(resourceGroup, vaultName, parameters).ConfigureAwait(false);

            return ToVaultModel(vault);
        }

        public async Task<List<CertificateModel>> GetCertificatesInVaultAsync(Uri vaultUri)
        {
            var totalItems = new List<CertificateProperties>();

            var certClient = new CertificateClient(vaultUri, appTokenCredential);            
            var certs = certClient.GetPropertiesOfCertificatesAsync(includePending:true).ConfigureAwait(false);
            await foreach(var cert in certs)
            {
                totalItems.Add(cert);
            }           

            var models = totalItems
                .Select(ci => new CertificateModel
                {
                    Name = ci.Name,
                    CertificateIdentifier = ci.Id,
                    Thumbprint = ci.X509Thumbprint != null ? BitConverter.ToString(ci.X509Thumbprint).Replace("-", "") : null,
                    Attributes = ci
                }).ToList();


            return models.OrderBy(cm => cm.Name).ToList();
        }

        public async Task<CertificateOperation> GetCertificateOperation(Uri vaultUrl, string certificateName)
        {            
            var client = new CertificateClient(vaultUrl, appTokenCredential);

            try
            {
                var op = await client.GetCertificateOperationAsync(certificateName).ConfigureAwait(false);
                return op;
            }
            catch (Azure.RequestFailedException e) when (e.Status == 404) // some older certs may be missing ops
            {
                return null;
            }            
        }

        public async Task<CertificateOperation> CreateCsrAsync(string vaultName, string certificateName, string commonName)
        {
            var policy = new CertificatePolicy("Unknown", $"CN={commonName}")
            {
                KeyType = CertificateKeyType.RsaHsm,
                KeySize = 4096
            };

            policy.KeyUsage.Add(CertificateKeyUsage.DigitalSignature);
            policy.EnhancedKeyUsage.Add("1.3.6.1.5.5.7.3.3"); // Code Signing

            var vault = await GetVaultAsync(vaultName).ConfigureAwait(false);

            var client = new CertificateClient(vault.VaultUri, appTokenCredential);
            var op = await client.StartCreateCertificateAsync(certificateName, policy).ConfigureAwait(false);            
            return op;
        }

        public async Task<DeleteCertificateOperation> CancelCsrAsync(string vaultName, string certificateName)
        {
            var vault = await GetVaultAsync(vaultName).ConfigureAwait(false);

            var client = new CertificateClient(vault.VaultUri, appTokenCredential);

            var op  = await client.StartDeleteCertificateAsync(certificateName);            

            return op;
        }

        public async Task<KeyVaultCertificateWithPolicy> MergeCertificate(string vaultName, string certificateName, byte[] certData)
        {
            // Get an X509CCertificate2Collection from the cert data
            // this supports either P7b or CER
            var publicCertificates = CryptoUtil.GetCertificatesFromCryptoData(certData);

            var vault = await GetVaultAsync(vaultName).ConfigureAwait(false);
            var certClient = new CertificateClient(vault.VaultUri, appTokenCredential);

            var chain = publicCertificates.Cast<X509Certificate2>().Select(c => c.RawData).ToArray();

            var options = new MergeCertificateOptions(certificateName, chain);
            var op = (await certClient.MergeCertificateAsync(options).ConfigureAwait(false)).Value;
            
            return op;
        }

        static VaultModel ToVaultModel(Vault vault)
        {
            string dname = null;
            string username = null;
            var model = new VaultModel
            {
                VaultUri = new Uri(vault.Properties.VaultUri.TrimEnd('/')),
                DisplayName = vault.Tags?.TryGetValue("displayName", out dname) == true ? dname : null,
                Username = vault.Tags?.TryGetValue("userName", out username) == true ? username : null,
                Name = vault.Name,
                Location = vault.Location
            };

            return model;
        }
    }
}
