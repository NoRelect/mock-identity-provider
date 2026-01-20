using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using MockIdentityProvider.Models;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace MockIdentityProvider.OpenIddict;

internal static class ClaimsPrincipalFactory
{
    public static ClaimsPrincipal Create(MockUser user, string? clientId, IEnumerable<string> scopes)
    {
        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);

        identity.AddClaim(new Claim(Claims.Subject, user.Id));
        if (!string.IsNullOrWhiteSpace(user.Name)) identity.AddClaim(new Claim(Claims.Name, user.Name));
        if (!string.IsNullOrWhiteSpace(user.Email)) identity.AddClaim(new Claim(Claims.Email, user.Email));
        if (!string.IsNullOrEmpty(clientId)) identity.AddClaim(new Claim(Claims.Audience, clientId));

        foreach (var role in user.Roles)
            identity.AddClaim(new Claim(Claims.Role, role));

        if (user.Claims is { Count: > 0 })
        {
            foreach (var (type, value) in user.Claims)
            {
                if (string.IsNullOrWhiteSpace(type)) continue;
                if (value is null) continue;

                identity.AddClaim(new Claim(type, value));
            }
        }

        identity.SetScopes(scopes);

        foreach (var claim in identity.Claims)
            claim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);

        return new ClaimsPrincipal(identity);
    }
}