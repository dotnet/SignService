using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Azure.ActiveDirectory.GraphClient;
using Microsoft.Azure.Management.ResourceManager;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;
//using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Rest;

namespace SignService.Services
{
    public interface IApplicationConfiguration
    {
        Task InitializeAsync();

        string ApplicationObjectId { get; }
        string PrimaryDomain { get; }

        string Location { get; }
    }

    class ApplicationConfiguration : IApplicationConfiguration
    {
        readonly MicrosoftIdentityOptions azureAdOptions;
        readonly IOptions<ResourceIds> resourceIds;
        readonly IOptions<AdminConfig> adminConfig;
        readonly ILogger<ApplicationConfiguration> logger;        

        public ApplicationConfiguration(IOptionsMonitor<MicrosoftIdentityOptions> azureAdOptions, IOptions<ResourceIds> resourceIds, IOptions<AdminConfig> adminConfig, ILogger<ApplicationConfiguration> logger)
        {
            this.azureAdOptions = azureAdOptions.Get(OpenIdConnectDefaults.AuthenticationScheme);
            //this.azureAdOptions = azureAdOptions.Get(AzureADDefaults.AuthenticationScheme);
            this.resourceIds = resourceIds;           
            this.adminConfig = adminConfig;
            this.logger = logger;
        }

        public async Task InitializeAsync()
        {
            logger.LogDebug("Retrieving application configuration data");
            // var redirect = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}";

            var conf = ConfidentialClientApplicationBuilder.Create(azureAdOptions.ClientId)
                       .WithClientSecret(azureAdOptions.ClientSecret)
                       .WithAuthority($"{azureAdOptions.Instance}{azureAdOptions.TenantId}")
                       .Build();


            //var authContext = new AuthenticationContext($"{azureAdOptions.Instance}{azureAdOptions.TenantId}", null);
            //var clientCredentials = new ClientCredential(azureAdOptions.ClientId, azureAdOptions.ClientSecret);
            


            // Use Graph to populate the Application Object Id and the Primary Domain
            var graphClient = new ActiveDirectoryClient(new Uri($"{adminConfig.Value.GraphInstance}{azureAdOptions.TenantId}"),
                                                        async () =>
                                                        {
                                                            //var result = await authContext.AcquireTokenAsync(resourceIds.Value.GraphId, clientCredentials);
                                                            //  var result = await tokenAcquisition.GetAuthenticationResultForAppAsync(resourceIds.Value.GraphId);

                                                            var result = await conf.AcquireTokenForClient(new[] { resourceIds.Value.GraphAppId }).ExecuteAsync().ConfigureAwait(false);
                                                            return result.AccessToken;
                                                        });



            var tenantDetails = await graphClient.TenantDetails.ExecuteAsync();
            var domains = tenantDetails.CurrentPage.First().VerifiedDomains;

            PrimaryDomain = domains.First(d => d.@default == true).Name;
            logger.LogInformation("Found Primary Domain {PrimaryDomain}", PrimaryDomain);

            var clientId = azureAdOptions.ClientId;
            var app = await graphClient.Applications.Where(a => a.AppId == clientId).ExecuteSingleAsync();


            ApplicationObjectId = app.ObjectId;

            logger.LogInformation("Found ApplicationObjectId {ApplicationObjectId} for ClientId {ClientId}", ApplicationObjectId, clientId);


            //var armAccessToken = await authContext.AcquireTokenAsync(resourceIds.Value.AzureRM, clientCredentials);
            var armAccessToken = await conf.AcquireTokenForClient(new[] { resourceIds.Value.AzureRMAppId } ).ExecuteAsync().ConfigureAwait(false);
            //var armAccessToken = await tokenAcquisition.GetAuthenticationResultForAppAsync(resourceIds.Value.AzureRM).ConfigureAwait(false);
            using var rgc = new ResourceManagementClient(new TokenCredentials(armAccessToken.AccessToken))
            {
                SubscriptionId = adminConfig.Value.SubscriptionId,
                BaseUri = new Uri(adminConfig.Value.ArmInstance)
            };

            // get the resource group
            var rg = await rgc.ResourceGroups.GetAsync(adminConfig.Value.ResourceGroup);

            Location = rg.Location;

            logger.LogInformation("Found Location {Location} for ResourceGroup {ResourceGroup}", Location, adminConfig.Value.ResourceGroup);
        }

        public string ApplicationObjectId { get; private set; }
        public string PrimaryDomain { get; private set; }
        public string Location { get; private set; }
    }
}
