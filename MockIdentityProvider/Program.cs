using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenIddict()
    .AddServer(options =>
    {
        options.IgnoreEndpointPermissions();
        options.IgnoreGrantTypePermissions();
        options.IgnoreResponseTypePermissions();
        options.IgnoreScopePermissions();
        options.AllowAuthorizationCodeFlow();
        options.AllowHybridFlow();
        options.AllowImplicitFlow();

        options.AddEphemeralEncryptionKey();
        options.AddEphemeralSigningKey();

        options.SetAuthorizationEndpointUris("/authorize");
        options.SetTokenEndpointUris("/token");
        options.SetUserinfoEndpointUris("/user-info");

        options.RegisterScopes("profile", "email", "role");

        options.EnableDegradedMode();
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

        options.AddEventHandler<HandleUserinfoRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                if(context.Principal.HasScope("role"))
                {
                    var role = context.Principal.FindFirstValue(Claims.Role);
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

                    List<string> users = ["admin", "author", "player"];

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
                    """ + Encoding.UTF8.GetString(JsonSerializer.SerializeToUtf8Bytes(users)) +
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
                                    elem.value = user;
                                    form.appendChild(elem);
                                }
                            </script>
                        </body>
                    </html>
                    """;
                    await request.HttpContext.Response.BodyWriter.WriteAsync(Encoding.UTF8.GetBytes(responseHtml));

                    return;
                }

                var user = request.Query["user"].Single()!;
                var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
                identity.AddClaim(new Claim(Claims.Subject, user));
                identity.AddClaim(new Claim(Claims.Name, user));
                identity.AddClaim(new Claim(Claims.Email, user+"@mock.idp"));
                identity.AddClaim(new Claim(Claims.Role, "hardcoded"));
                identity.SetScopes(context.Request.GetScopes());

                foreach (var claim in identity.Claims)
                {
                    claim.SetDestinations(Destinations.AccessToken);
                }

                context.Principal = new ClaimsPrincipal(identity);
            }));
    });

var app = builder.Build();

app.UseForwardedHeaders();
app.UseDefaultFiles();
app.UseStaticFiles();

app.Run();
