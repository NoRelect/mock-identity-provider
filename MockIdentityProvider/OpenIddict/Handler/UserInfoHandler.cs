using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace MockIdentityProvider.OpenIddict;

internal static class UserInfoHandler
{
    public static ValueTask Handle(HandleUserInfoRequestContext context)
    {
        foreach (var claim in context.AccessTokenPrincipal.Claims)
        {
            if (string.IsNullOrWhiteSpace(claim.Type)) continue;

            if (claim.Type is Claims.Audience or Claims.ExpiresAt or Claims.IssuedAt or Claims.NotBefore) continue;
            if (claim.Type is Claims.JwtId or Claims.ClientId or Claims.Private.TokenId) continue;
            if (claim.Type is Claims.Private.Scope or Claims.Private.Presenter) continue;

            context.Claims[claim.Type] = new OpenIddictParameter(claim.Value);
        }

        return default;
    }
}