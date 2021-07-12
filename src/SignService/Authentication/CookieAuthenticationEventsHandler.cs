using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Azure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;

using SignService.Models;

namespace SignService.Authentication
{
    public class CookieAuthenticationEventsHandler : CookieAuthenticationEvents
    {
        public async override Task ValidatePrincipal(CookieValidatePrincipalContext context)
        {
            try
            {
                var tokenAcquisition = context.HttpContext.RequestServices.GetRequiredService<ITokenAcquisition>();
                var token = await tokenAcquisition.GetAccessTokenForUserAsync(
                    scopes: new[] { "profile" },
                    user: context.Principal);
            }
            catch (MicrosoftIdentityWebChallengeUserException ex)
               when (AccountDoesNotExitInTokenCache(ex))
            {
                context.RejectPrincipal();
            }
        }

        /// <summary>
        /// Is the exception thrown because there is no account in the token cache?
        /// </summary>
        /// <param name="ex">Exception thrown by <see cref="ITokenAcquisition"/>.GetTokenForXX methods.</param>
        /// <returns>A boolean telling if the exception was about not having an account in the cache</returns>
        private static bool AccountDoesNotExitInTokenCache(MicrosoftIdentityWebChallengeUserException ex)
        {
            return ex.InnerException is MsalUiRequiredException
                                      && (ex.InnerException as MsalUiRequiredException).ErrorCode == "user_null";
        }
    }
}
