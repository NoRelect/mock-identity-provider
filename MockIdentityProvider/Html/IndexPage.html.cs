using MockIdentityProvider.Configuration;
using Scriban;

namespace MockIdentityProvider.Html;

internal static class IndexPage
{
    private static readonly Lazy<Scriban.Template> ParsedTemplate = new(() =>
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Html", "Templates", "Index.scriban");
        var text = File.ReadAllText(path);

        var template = Scriban.Template.Parse(text);
        if (template.HasErrors)
            throw new InvalidOperationException(string.Join(Environment.NewLine, template.Messages));

        return template;
    });

    public static string Render(MockIdpRootConfig cfg)
    {
        var endpoints = new[]
        {
            new { path = "/.well-known/openid-configuration", purpose = "Discovery document" },
            new { path = "/authorize", purpose = "Authorization endpoint (user selection UI)" },
            new { path = "/token", purpose = "Token endpoint" },
            new { path = "/user-info", purpose = "UserInfo endpoint" },
            new { path = "/logout", purpose = "End session endpoint" },
            new { path = "/revoke", purpose = "Revocation endpoint" }
        };

        var flows = new[]
        {
            new { name = "Authorization Code", enabled = cfg.AllowAuthorizationCodeFlow },
            new { name = "Hybrid", enabled = cfg.AllowHybridFlow },
            new { name = "Implicit", enabled = cfg.AllowImplicitFlow },
            new { name = "Refresh Token", enabled = cfg.AllowRefreshTokenFlow },
            new { name = "Password (ROPC)", enabled = cfg.AllowPasswordFlow },
            new { name = "None", enabled = cfg.AllowNoneFlow }
        };

        var users = cfg.Users
            .Select(u => new
            {
                id = u.Id,
                name = u.Name ?? "",
                email = u.Email ?? "",
                roles = u.Roles is { Count: > 0 } ? string.Join(", ", u.Roles) : "",
                claims = u.Claims is { Count: > 0 }
                    ? string.Join(", ", u.Claims.OrderBy(x => x.Key).Select(x => $"{x.Key}={x.Value}"))
                    : ""
            })
            .ToList();

        var defaultUser = cfg.Users.FirstOrDefault(u => u.Id != "error") ?? cfg.Users.FirstOrDefault();

        var model = new
        {
            title = "Mock IdP",
            brand = "Mock Identity Provider",
            heading = "Mock Identity Provider",
            description = "OpenID Connect / OAuth2 mock server for development, testing and automation.",
            issuer = cfg.Issuer,
            registered_scopes = "openid profile email role",
            default_client_id = "test",
            default_scope = "openid profile email role",
            default_response_type = "id_token token",
            default_nonce = "hardcoded",
            default_username = defaultUser?.Id ?? "admin",
            endpoints,
            flows,
            users
        };

        return ParsedTemplate.Value.Render(model, m => m.Name);
    }
}
