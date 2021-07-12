using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;

using Newtonsoft.Json;
using SignService.Models;
using SignService.Services;

namespace SignService.Authentication
{
    public class JwtBearerEventsHandler : JwtBearerEvents
    {
        public override async Task TokenValidated(TokenValidatedContext context)
        {
            var contextAccessor = context.HttpContext.RequestServices.GetRequiredService<IHttpContextAccessor>();
            var azureOptions = context.HttpContext.RequestServices.GetRequiredService<IOptionsMonitor<MicrosoftIdentityOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);
            var settings = context.HttpContext.RequestServices.GetRequiredService<IOptions<ResourceIds>>().Value;
            var adminOptions = context.HttpContext.RequestServices.GetRequiredService<IOptions<AdminConfig>>().Value;
            var tokenAquisition = context.HttpContext.RequestServices.GetRequiredService<ITokenAcquisition>();

            var passed = false;

            var identity = (ClaimsIdentity)context.Principal.Identity;

            // See if there's a UPN, and if so, use that object id
            var upn = identity.Claims.FirstOrDefault(c => c.Type == "upn")?.Value;
            if (upn != null)
            {
                var oid = identity.Claims.FirstOrDefault(c => c.Type == "oid")?.Value;

                // get the user
                //var authContext = new AuthenticationContext($"{azureOptions.Instance}{azureOptions.TenantId}", null); // No token caching
                //var credential = new ClientCredential(azureOptions.ClientId, azureOptions.ClientSecret);

                var incomingToken = ((JwtSecurityToken)context.SecurityToken).RawData;

                // Prime the KV access token concurrently
                var kvService = contextAccessor.HttpContext.RequestServices.GetRequiredService<IKeyVaultService>();
                var kvTokenTask = kvService.InitializeAccessTokenAsync(incomingToken);

                // see if we need to get tokens from the graph at all, might be in the claim if the manifest was updated
                var hasClaimsInToken = bool.TryParse(identity.Claims.FirstOrDefault(c => c.Type == "extn.signServiceConfigured")?.Value, out var signServiceConfigured);
                GraphUser user = null;

                if (hasClaimsInToken)
                {
                    user = new GraphUser
                    {
                        DisplayName = identity.Claims.FirstOrDefault(c => c.Type == "name")?.Value,
                        SignServiceConfigured = signServiceConfigured,
                        KeyVaultUrl = new Uri(identity.Claims.FirstOrDefault(c => c.Type == "extn.keyVaultUrl")?.Value.TrimEnd('/')),
                        KeyVaultCertificateName = identity.Claims.FirstOrDefault(c => c.Type == "extn.keyVaultCertificateName")?.Value,
                        TimestampUrl = identity.Claims.FirstOrDefault(c => c.Type == "extn.timestampUrl")?.Value
                    };
                }
                else // get them from the graph directly
                {
                    //var result = await authContext.AcquireTokenAsync(settings.GraphId, credential, new UserAssertion(incomingToken));
                    var result = await tokenAquisition.GetAuthenticationResultForUserAsync(new[] { settings.GraphUserId }).ConfigureAwait(false);

                    var url = $"{adminOptions.GraphInstance}{azureOptions.TenantId}/users/{oid}?api-version=1.6";

                    using var client = new HttpClient();
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
                    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    var resp = await client.GetAsync(url).ConfigureAwait(false);
                    if (resp.IsSuccessStatusCode)
                    {
                        user = JsonConvert.DeserializeObject<GraphUser>(await resp.Content.ReadAsStringAsync().ConfigureAwait(false));
                    }
                }

                if (user?.SignServiceConfigured == true)
                {
                    passed = true;

                    identity.AddClaim(new Claim("keyVaultUrl", user.KeyVaultUrl.ToString()));
                    identity.AddClaim(new Claim("keyVaultCertificateName", user.KeyVaultCertificateName));
                    identity.AddClaim(new Claim("timestampUrl", user.TimestampUrl));
                }

                // Wait for the KV task to finish
                await kvTokenTask.ConfigureAwait(false);
                kvService.InitializeCertificateInfo(user.TimestampUrl, user.KeyVaultUrl, user.KeyVaultCertificateName);
            }

            if (!passed)
            {
                // If we get here, it's an unknown value
                context.Fail("User is not configured");
            }
        }
    }
}
