using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;
//using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using SignService.Models;

namespace SignService.Services
{
    public class GraphHttpService : IGraphHttpService
    {
        readonly MicrosoftIdentityOptions azureAdOptions;
        readonly AdminConfig adminConfig;
        //readonly AuthenticationContext adalContext;
        readonly ITokenAcquisition tokenAcquisition;
        static readonly HttpMethod PatchMethod = new("PATCH");
        readonly string graphUserResourceId;
        readonly string graphAppResourceId;

        public GraphHttpService(IOptionsSnapshot<MicrosoftIdentityOptions> azureAdOptions, IOptionsSnapshot<AdminConfig> adminConfig, IOptionsSnapshot<ResourceIds> resources, IUser user, ITokenAcquisition tokenAcquisition, IHttpContextAccessor contextAccessor)
        {
            this.azureAdOptions = azureAdOptions.Get(OpenIdConnectDefaults.AuthenticationScheme);
            this.adminConfig = adminConfig.Value;
            this.tokenAcquisition = tokenAcquisition;
            graphAppResourceId = resources.Value.GraphAppId;
            graphUserResourceId = resources.Value.GraphUserId;

            var userId = user.ObjectId;

           // adalContext = new AuthenticationContext($"{this.azureAdOptions.Instance}{this.azureAdOptions.TenantId}", new ADALSessionCache(userId, contextAccessor));
        }

        public async Task<List<T>> Get<T>(string url)
        {
            using var client = await CreateClient()
                                    .ConfigureAwait(false);
            var response = await client.GetAsync($"{azureAdOptions.TenantId}/{url}").ConfigureAwait(false);

            var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var formatted = JsonConvert.DeserializeObject<ODataErrorWrapper>(responseContent);
                throw new WebException("Error Calling the Graph API get: \n" +
                                       JsonConvert.SerializeObject(formatted, Formatting.Indented));
            }

            var result = JsonConvert.DeserializeObject<ODataCollection<T>>(responseContent);
            return result.Value;
        }

        public async Task<T> GetScalar<T>(string url)
        {
            using var client = await CreateClient()
                                    .ConfigureAwait(false);
            var response = await client.GetAsync($"{azureAdOptions.TenantId}/{url}").ConfigureAwait(false);

            var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var formatted = JsonConvert.DeserializeObject<ODataErrorWrapper>(responseContent);
                throw new WebException("Error Calling the Graph API get: \n" +
                                       JsonConvert.SerializeObject(formatted, Formatting.Indented));
            }

            var result = JsonConvert.DeserializeObject<T>(responseContent);
            return result;
        }

        public async Task<T> GetValue<T>(string url)
        {
            using var client = await CreateClient()
                                    .ConfigureAwait(false);
            var response = await client.GetAsync($"{azureAdOptions.TenantId}/{url}").ConfigureAwait(false);

            var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var formatted = JsonConvert.DeserializeObject<ODataErrorWrapper>(responseContent);
                throw new WebException("Error Calling the Graph API get: \n" +
                                       JsonConvert.SerializeObject(formatted, Formatting.Indented));
            }

            var result = JsonConvert.DeserializeObject<ODataScalar<T>>(responseContent);
            return result.Value;
        }

        public async Task Delete(string url, bool accessAsUser = false)
        {
            using var client = await CreateClient(accessAsUser)
                                    .ConfigureAwait(false);
            var response = await client.DeleteAsync($"{azureAdOptions.TenantId}/{url}").ConfigureAwait(false);

            var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var formatted = JsonConvert.DeserializeObject<ODataErrorWrapper>(responseContent);
                throw new WebException("Error Calling the Graph API to delete: \n" +
                                       JsonConvert.SerializeObject(formatted, Formatting.Indented));
            }
        }

        public async Task<TOutput> Post<TInput, TOutput>(string url, TInput item, bool accessAsUser = false)
        {
            using var client = await CreateClient(accessAsUser)
                                    .ConfigureAwait(false);
            var skipNulls = new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore
            };
            var request = new StringContent(JsonConvert.SerializeObject(item, skipNulls), Encoding.UTF8, "application/json");

            var response = await client.PostAsync($"{azureAdOptions.TenantId}/{url}", request).ConfigureAwait(false);
            var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var formatted = JsonConvert.DeserializeObject<ODataErrorWrapper>(responseContent);
                throw new WebException("Error Calling the Graph API to update: \n" +
                                       JsonConvert.SerializeObject(formatted, Formatting.Indented));
            }

            return JsonConvert.DeserializeObject<TOutput>(responseContent);
        }


        public async Task Patch<TInput>(string url, TInput item, bool accessAsUser = false)
        {
            var contentBody = JsonConvert.SerializeObject(item);

            await Patch(url, contentBody, accessAsUser).ConfigureAwait(false);
        }

        public async Task Patch(string url, string contentBody, bool accessAsUser = false)
        {
            using var client = await CreateClient(accessAsUser)
                                    .ConfigureAwait(false);
            var request = new HttpRequestMessage(PatchMethod, $"{azureAdOptions.TenantId}/{url}")
            {
                Content = new StringContent(contentBody, Encoding.UTF8, "application/json")
            };

            var response = await client.SendAsync(request).ConfigureAwait(false);
            var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var formatted = JsonConvert.DeserializeObject<ODataErrorWrapper>(responseContent);
                throw new WebException("Error Calling the Graph API to update: \n" +
                                       JsonConvert.SerializeObject(formatted, Formatting.Indented));
            }
        }

        async Task<HttpClient> CreateClient(bool accessAsUser = false)
        {
            AuthenticationResult result;
            if (accessAsUser)
            {
                //result = await adalContext.AcquireTokenSilentAsync(graphResourceId, azureAdOptions.ClientId).ConfigureAwait(false);
                result = await tokenAcquisition.GetAuthenticationResultForUserAsync(new[] { graphUserResourceId }).ConfigureAwait(false);
            }
            else
            {
                //result = await adalContext.AcquireTokenAsync(graphResourceId, new ClientCredential(azureAdOptions.ClientId, azureAdOptions.ClientSecret)).ConfigureAwait(false);
                result = await tokenAcquisition.GetAuthenticationResultForAppAsync(graphAppResourceId).ConfigureAwait(false);
            }

            var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
            client.DefaultRequestHeaders
                   .Accept
                   .Add(new MediaTypeWithQualityHeaderValue("application/json"));
            client.BaseAddress = new Uri(adminConfig.GraphInstance);

            return client;
        }
    }
}
