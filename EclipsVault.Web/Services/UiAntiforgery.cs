using Microsoft.AspNetCore.Antiforgery;

namespace EclipsVault.Web.Services;

/// <summary>Refreshes Angular's request token, including when a stale session must POST sign-out.</summary>
public static class UiAntiforgery
{
    public static void IssueToken(HttpContext context, IAntiforgery antiforgery)
    {
        var tokens = antiforgery.GetAndStoreTokens(context);
        context.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!, new CookieOptions
        {
            HttpOnly = false,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/",
        });
    }
}
