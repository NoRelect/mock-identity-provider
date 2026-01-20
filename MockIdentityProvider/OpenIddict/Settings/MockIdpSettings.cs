using MockIdentityProvider.Models;

namespace MockIdentityProvider.Configuration;

public sealed class MockIdpRootConfig
{
    public string Issuer { get; init; } = "";
    public bool AllowAuthorizationCodeFlow { get; init; } = true;
    public bool AllowHybridFlow { get; init; } = true;
    public bool AllowImplicitFlow { get; init; } = true;
    public bool AllowRefreshTokenFlow { get; init; } = true;
    public bool AllowPasswordFlow { get; init; } = true;
    public bool AllowNoneFlow { get; init; } = true;
    public List<MockUser> Users { get; init; } = [];
}