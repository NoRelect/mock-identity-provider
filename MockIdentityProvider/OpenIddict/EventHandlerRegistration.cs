using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace MockIdentityProvider.OpenIddict;

internal static class EventHandlerRegistration
{
    public static void Register(OpenIddictServerBuilder options)
    {
        options.AddEventHandler<ValidateAuthorizationRequestContext>(b => b.UseInlineHandler(_ => default));
        options.AddEventHandler<ValidateTokenRequestContext>(b => b.UseInlineHandler(_ => default));
        options.AddEventHandler<ValidateRevocationRequestContext>(b => b.UseInlineHandler(_ => default));
        options.AddEventHandler<ValidateEndSessionRequestContext>(b => b.UseInlineHandler(_ => default));

        options.AddEventHandler<HandleAuthorizationRequestContext>(b => b.UseInlineHandler(AuthorizationHandler.Handle));
        options.AddEventHandler<HandleTokenRequestContext>(b => b.UseInlineHandler(TokenHandler.Handle));
        options.AddEventHandler<HandleUserInfoRequestContext>(b => b.UseInlineHandler(UserInfoHandler.Handle));
        options.AddEventHandler<HandleRevocationRequestContext>(b => b.UseInlineHandler(RevocationHandler.Handle));
        options.AddEventHandler<HandleEndSessionRequestContext>(b => b.UseInlineHandler(EndSessionHandler.Handle));
    }
}

internal static class RevocationHandler
{
    public static ValueTask Handle(HandleRevocationRequestContext context)
    {
        context.HandleRequest();
        return ValueTask.CompletedTask;
    }
}

internal static class EndSessionHandler
{
    public static ValueTask Handle(HandleEndSessionRequestContext context)
    {
        context.SignOut();
        return ValueTask.CompletedTask;
    }
}