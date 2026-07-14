namespace EclipsVault.Web.Middleware;

/// <summary>Injects defence-in-depth headers on every response.</summary>
public sealed class SecurityHeadersMiddleware
{
    private const string ContentSecurityPolicy =
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self'; " +
        "img-src 'self' data:; " +
        "font-src 'self'; " +
        "connect-src 'self'; " +
        "object-src 'none'; " +      // no <object>/<embed>/<applet> plugin vectors
        "frame-src 'none'; " +       // the app embeds no iframes
        "frame-ancestors 'none'; " + // and refuses to be embedded (clickjacking)
        "form-action 'self'; " +
        "base-uri 'self'";

    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next) => _next = next;

    public Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;
        headers["Content-Security-Policy"] = ContentSecurityPolicy;
        headers["X-Frame-Options"] = "DENY";
        headers["X-Content-Type-Options"] = "nosniff";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Permissions-Policy"] =
            "camera=(), geolocation=(), microphone=(), payment=(), " +
            "publickey-credentials-get=(self), publickey-credentials-create=(self)";
        headers["Cross-Origin-Opener-Policy"] = "same-origin";
        // Our resources (avatars, static assets) are only ever loaded same-origin behind auth,
        // so refuse to be pulled into any other site's document.
        headers["Cross-Origin-Resource-Policy"] = "same-origin";
        // No legacy Flash/PDF cross-domain policy files are honoured.
        headers["X-Permitted-Cross-Domain-Policies"] = "none";

        return _next(context);
    }
}
