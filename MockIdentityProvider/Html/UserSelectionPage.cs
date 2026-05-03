using System.Text;
using Scriban;
using MockIdentityProvider.Models;

namespace MockIdentityProvider.Html;

internal static class UserSelectionPage
{
    private static readonly Lazy<Scriban.Template> ParsedTemplate = new(() =>
    {
        var path = Path.Combine(
            AppContext.BaseDirectory,
            "Html",
            "Templates",
            "UserSelectionPage.scriban");

        var text = File.ReadAllText(path);

        var template = Scriban.Template.Parse(text);

        if (template.HasErrors)
        {
            var errors = string.Join(Environment.NewLine, template.Messages);
            throw new InvalidOperationException($"Scriban template error:{Environment.NewLine}{errors}");
        }

        return template;
    });

    public static string Render(IEnumerable<MockUser> users, string issuer)
    {
        var model = new
        {
            issuer,
            users = users.Select(u => new
            {
                id = u.Id,
                name = u.Name,
                email = u.Email,
                roles = u.Roles ?? [],
                search = BuildSearchBlob(u)
            })
        };

        return ParsedTemplate.Value.Render(model, member => member.Name);
    }

    private static string BuildSearchBlob(MockUser u)
    {
        var claims = u.Claims ?? new Dictionary<string, string>();

        return string.Join(" ",
            new[]
                {
                    u.Id,
                    u.Name,
                    u.Email
                }
                .Concat(u.Roles ?? [])
                .Concat(claims.SelectMany(c => new[] { c.Key, c.Value }))
                .Where(v => !string.IsNullOrWhiteSpace(v))
        ).ToLowerInvariant();
    }
}