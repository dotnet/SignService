using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;

using SignService.Models;

namespace SignService.Authentication
{
    public class OpenIdConnectEventsHandler : OpenIdConnectEvents
    {
        //public override async Task AuthorizationCodeReceived(AuthorizationCodeReceivedContext context)
        //{
        //    var contextAccessor = context.HttpContext.RequestServices.GetRequiredService<IHttpContextAccessor>();
        //    var azureOptions = context.HttpContext.RequestServices.GetRequiredService<IOptionsMonitor<AzureADOptions>>().Get(AzureADDefaults.AuthenticationScheme);
        //    var tokenGetter = context.HttpContext.RequestServices.GetRequiredService<ITokenAcquisition>();
            


        //    var userId = context.Principal.FindFirst("oid").Value;

        //    var adal = new AuthenticationContext($"{azureOptions.Instance}{azureOptions.TenantId}", new ADALSessionCache(userId, contextAccessor));

        //    var redirect = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}";
        //    // Store in cache for later redemption

        //    var res = await adal.AcquireTokenByAuthorizationCodeAsync(context.ProtocolMessage.Code, new Uri(redirect), new ClientCredential(azureOptions.ClientId, azureOptions.ClientSecret), "https://graph.windows.net");

        //    context.HandleCodeRedemption(res.AccessToken, res.IdToken);
        //}
    }
}
