using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore;
using Microsoft.IdentityModel.Tokens;
using MockIdentityProvider.Models;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

var builder = WebApplication.CreateBuilder(args);

var issuerUrl = builder.Configuration.GetSection("Issuer").Get<string>()
    ?? throw new InvalidOperationException("Issuer URL must be set.");
var mockUsers = builder.Configuration.GetSection("Users").Get<List<MockUser>>() ?? [];
mockUsers.Add(new MockUser { Id = "error", Name = "error" });

builder.Services.AddOpenIddict()
    .AddServer(options =>
    {
        options.IgnoreEndpointPermissions();
        options.IgnoreGrantTypePermissions();
        options.IgnoreResponseTypePermissions();
        options.IgnoreScopePermissions();
        if (builder.Configuration.GetValue("AllowAuthorizationCodeFlow", true))
        {
            options.AllowAuthorizationCodeFlow();
        }
        if (builder.Configuration.GetValue("AllowHybridFlow", true))
        {
            options.AllowHybridFlow();
        }
        if (builder.Configuration.GetValue("AllowImplicitFlow", true))
        {
            options.AllowImplicitFlow();
        }
        if (builder.Configuration.GetValue("AllowRefreshTokenFlow", true))
        {
            options.AllowRefreshTokenFlow();
        }
        if (builder.Configuration.GetValue("AllowPasswordFlow", true))
        {
            options.AllowPasswordFlow();
        }
        if (builder.Configuration.GetValue("AllowNoneFlow", true))
        {
            options.AllowNoneFlow();
        }
        options.AddEphemeralEncryptionKey();
        options.AddEphemeralSigningKey();

        options.SetAuthorizationEndpointUris("/authorize");
        options.SetTokenEndpointUris("/token");
        options.SetUserInfoEndpointUris("/user-info");
        options.SetEndSessionEndpointUris("/logout");

        options.RegisterScopes("profile", "email", "role");
        options.DisableScopeValidation();

        options.AcceptAnonymousClients();
        options.SetIssuer(issuerUrl);
        options.EnableDegradedMode();
        options.DisableAccessTokenEncryption();
        options.UseAspNetCore()
            .DisableTransportSecurityRequirement();

        options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                // Allow any authorization request
                return default;
            }));

        options.AddEventHandler<ValidateTokenRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                // Allow any token request
                return default;
            }));

        options.AddEventHandler<ValidateEndSessionRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                // Allow any logout request
                return default;
            }));

        options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                if (context.AccessTokenPrincipal.HasScope("profile"))
                {
                    var name = context.AccessTokenPrincipal.FindFirstValue(Claims.Name);
                    context.Claims.Add(Claims.Name, new OpenIddictParameter(name));
                }
                if (context.AccessTokenPrincipal.HasScope("role"))
                {
                    var role = context.AccessTokenPrincipal.FindFirstValue(Claims.Role);
                    context.Claims.Add(Claims.Role, new OpenIddictParameter(role));
                }
                return default;
            }));

        options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
            builder.UseInlineHandler(async context =>
            {
                var request = context.Transaction.GetHttpRequest() ??
                    throw new InvalidOperationException("The ASP.NET Core request cannot be retrieved.");

                if (!request.Query.ContainsKey("user"))
                {
                    context.HandleRequest();

                    var responseHtml = """
                    <!doctype html>
                    <html lang="en">
                        <head>
                            <meta charset="utf-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1">
                            <meta name="color-scheme" content="light dark">
                            <link rel="stylesheet" href="css/pico.min.css">
                            <title>MIdP | Select</title>
                        </head>
                        <body>
                            <main class="container">
                                <nav>
                                    <ul>
                                        <li><strong>Mock IdP - User Selection</strong></li>
                                    </ul>
                                </nav>
                                <form id="form">
                                </form>
                            </main>
                            <script>
                                const users =
                    """ + Encoding.UTF8.GetString(JsonSerializer.SerializeToUtf8Bytes(mockUsers)) +
                    """
                    ;
                                let form = document.getElementById("form");
                                let params = new URLSearchParams(window.location.search);
                                for (const [key, value] of params) {
                                    var elem = document.createElement("input");
                                    elem.type = "hidden";
                                    elem.name = key;
                                    elem.value = value;
                                    form.appendChild(elem);
                                }
                                for (let user of users) {
                                    var elem = document.createElement("input");
                                    elem.type = "submit";
                                    elem.name = "user";
                                    elem.value = user.Id;
                                    form.appendChild(elem);
                                }
                            </script>
                        </body>
                    </html>
                    """;
                    await request.HttpContext.Response.BodyWriter.WriteAsync(Encoding.UTF8.GetBytes(responseHtml));

                    return;
                }

                var user = request.Query["user"].SingleOrDefault();

                if (user == "error")
                {
                    context.Reject("error-name", "This is the error description", "https://example.com");
                    return;
                }

                var mockUser = mockUsers.FirstOrDefault(u => u.Id == user);
                if (mockUser == null)
                {
                    context.HandleRequest();
                    await request.HttpContext.Response.BodyWriter.WriteAsync(Encoding.UTF8.GetBytes("Invalid user selected."));
                    return;
                }
                var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
                identity.AddClaim(new Claim(Claims.Subject, mockUser.Id));
                identity.AddClaim(new Claim(Claims.Name, mockUser.Name));
                identity.AddClaim(new Claim(Claims.Email, mockUser.Email));
                if (!string.IsNullOrEmpty(context.Request.ClientId))
                    identity.AddClaim(new Claim(Claims.Audience, context.Request.ClientId));
                foreach (var role in mockUser.Roles)
                {
                    identity.AddClaim(new Claim(Claims.Role, role));
                }
                identity.SetScopes(context.Request.GetScopes());

                foreach (var claim in identity.Claims)
                {
                    claim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
                }

                context.Principal = new ClaimsPrincipal(identity);
            }));

        options.AddEventHandler<HandleTokenRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                var request = context.Transaction.GetHttpRequest() ??
                    throw new InvalidOperationException("The ASP.NET Core request cannot be retrieved.");

                if (context.Request.GrantType == GrantTypes.Password)
                {
                    var user = context.Request.Username;

                    var mockUser = mockUsers.FirstOrDefault(u => u.Id == user);
                    if (mockUser == null)
                    {
                        context.Reject("Invalid user selected.");
                        return ValueTask.CompletedTask;
                    }
                    var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
                    identity.AddClaim(new Claim(Claims.Subject, mockUser.Id));
                    identity.AddClaim(new Claim(Claims.Name, mockUser.Name));
                    identity.AddClaim(new Claim(Claims.Email, mockUser.Email));
                    if (!string.IsNullOrEmpty(context.Request.ClientId))
                        identity.AddClaim(new Claim(Claims.Audience, context.Request.ClientId));
                    foreach (var role in mockUser.Roles)
                    {
                        identity.AddClaim(new Claim(Claims.Role, role));
                    }
                    identity.SetScopes(context.Request.GetScopes());

                    foreach (var claim in identity.Claims)
                    {
                        claim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
                    }

                    context.Principal = new ClaimsPrincipal(identity);
                    return ValueTask.CompletedTask;
                }
                return ValueTask.CompletedTask;
            }));

        options.AddEventHandler<HandleEndSessionRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                return ValueTask.CompletedTask;
            }));
    });

builder.Services.AddAuthentication();
builder.Services.AddAuthorization();

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy => policy
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowAnyOrigin());
});

var app = builder.Build();

app.UseForwardedHeaders();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.Run();
