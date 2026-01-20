using MockIdentityProvider.Configuration;
using MockIdentityProvider.Html;
using MockIdentityProvider.OpenIddict;

var builder = WebApplication.CreateBuilder(args);

var config = builder.Configuration.Get<MockIdpRootConfig>()
             ?? throw new InvalidOperationException("Configuration must be configured.");

config.Users.Add(new() { Id = "error", Name = "error" });

builder.Services.AddSingleton(config);

builder.Services.AddAuthentication();
builder.Services.AddAuthorization();

builder.Services.AddCors(o =>
{
    o.AddDefaultPolicy(p =>
        p.AllowAnyHeader()
            .AllowAnyMethod()
            .AllowAnyOrigin());
});

builder.Services.AddMockOpenIddict(builder.Configuration);

var app = builder.Build();

app.UseForwardedHeaders();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/", async (HttpContext ctx, MockIdpRootConfig cfg) =>
{
    ctx.Response.ContentType = "text/html; charset=utf-8";
    await ctx.Response.WriteAsync(IndexPage.Render(cfg));
});

app.Run();