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
        "frame-ancestors 'none'; " +
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

        return _next(context);
    }
}
