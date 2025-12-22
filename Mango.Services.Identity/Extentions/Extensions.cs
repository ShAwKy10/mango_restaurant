using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;

namespace Mango.Services.Identity
{
    public static class Extensions
    {
        /// <summary>
        /// Checks if the authentication scheme supports signout.
        /// </summary>
        public static async Task<bool> GetSchemeSupportsSignOutAsync(this HttpContext context, string scheme)
        {
            var provider = context.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
            var handler = await provider.GetHandlerAsync(context, scheme);
            return (handler is IAuthenticationSignOutHandler);
        }
    }
}