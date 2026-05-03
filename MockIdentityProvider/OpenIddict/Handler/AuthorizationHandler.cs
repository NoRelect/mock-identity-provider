using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore;
using Microsoft.IdentityModel.Tokens;
using MockIdentityProvider.Configuration;
using MockIdentityProvider.Html;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace MockIdentityProvider.OpenIddict;

internal static class AuthorizationHandler
{
    public static async ValueTask Handle(HandleAuthorizationRequestContext context)
    {
        var request = context.Transaction.GetHttpRequest()
                      ?? throw new InvalidOperationException();

        var settings = request.HttpContext.RequestServices
            .GetRequiredService<MockIdpRootConfig>();

        if (!request.Query.ContainsKey("user"))
        {
            context.HandleRequest();
            await HtmlResponse.Write(
                request,
                UserSelectionPage.Render(settings.Users, settings.Issuer)
            );
            return;
        }

        var userId = request.Query["user"].Single();

        if (userId == "error")
        {
            context.Reject("error-name", "This is the error description", "https://example.com");
            return;
        }

        var user = settings.Users!.FirstOrDefault(u => u.Id == userId);
        if (user == null)
        {
            context.HandleRequest();
            await HtmlResponse.Write(request, "Invalid user selected.");
            return;
        }

        context.Principal = ClaimsPrincipalFactory.Create(
            user,
            context.Request.ClientId,
            context.Request.GetScopes());
    }
}