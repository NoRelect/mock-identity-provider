using System.Text;

namespace MockIdentityProvider.Html;

internal static class HtmlResponse
{
    public static async Task Write(
        Microsoft.AspNetCore.Http.HttpRequest request,
        string content)
    {
        request.HttpContext.Response.ContentType = "text/html; charset=utf-8";
        await request.HttpContext.Response.BodyWriter
            .WriteAsync(Encoding.UTF8.GetBytes(content));
    }
}
