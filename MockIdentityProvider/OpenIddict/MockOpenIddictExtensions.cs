using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MockIdentityProvider.Configuration;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;

namespace MockIdentityProvider.OpenIddict;

public static class MockOpenIddictExtensions
{
    public static IServiceCollection AddMockOpenIddict(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOpenIddict().AddServer(options =>
        {
            options.IgnoreEndpointPermissions();
            options.IgnoreGrantTypePermissions();
            options.IgnoreResponseTypePermissions();
            options.IgnoreScopePermissions();

            var root = configuration.Get<MockIdpRootConfig>()
                ?? throw new InvalidOperationException("Configuration must be configured.");

            if (root.AllowAuthorizationCodeFlow) options.AllowAuthorizationCodeFlow();
            if (root.AllowHybridFlow) options.AllowHybridFlow();
            if (root.AllowImplicitFlow) options.AllowImplicitFlow();
            if (root.AllowRefreshTokenFlow) options.AllowRefreshTokenFlow();
            if (root.AllowPasswordFlow) options.AllowPasswordFlow();
            if (root.AllowNoneFlow) options.AllowNoneFlow();

            options.AddEphemeralEncryptionKey();
            options.AddEphemeralSigningKey();

            options.SetAuthorizationEndpointUris("/authorize");
            options.SetTokenEndpointUris("/token");
            options.SetUserInfoEndpointUris("/user-info");
            options.SetEndSessionEndpointUris("/logout");
            options.SetRevocationEndpointUris("/revoke");

            options.RegisterScopes("profile", "email", "role");
            options.DisableScopeValidation();

            options.AcceptAnonymousClients();
            options.SetIssuer(root.Issuer);
            options.EnableDegradedMode();
            options.DisableAccessTokenEncryption();

            options.UseAspNetCore().DisableTransportSecurityRequirement();

            EventHandlerRegistration.Register(options);
        });

        return services;
    }
}
