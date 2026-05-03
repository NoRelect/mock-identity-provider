using Microsoft.AspNetCore;
using MockIdentityProvider.Configuration;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace MockIdentityProvider.OpenIddict;

internal static class TokenHandler
{
    public static ValueTask Handle(HandleTokenRequestContext context)
    {
        if (context.Request.GrantType != GrantTypes.Password)
            return ValueTask.CompletedTask;

        var request = context.Transaction.GetHttpRequest()
                      ?? throw new InvalidOperationException();

        var settings = request.HttpContext.RequestServices
            .GetRequiredService<MockIdpRootConfig>();

        var user = settings.Users!
            .FirstOrDefault(u => u.Id == context.Request.Username);

        if (user == null)
        {
            context.Reject("Invalid user selected.");
            return ValueTask.CompletedTask;
        }

        context.Principal = ClaimsPrincipalFactory.Create(
            user,
            context.Request.ClientId,
            context.Request.GetScopes());

        return ValueTask.CompletedTask;
    }
}