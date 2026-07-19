using EclipsVault.Core.Domain.Exceptions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace EclipsVault.Web.Middleware;

/// <summary>
/// Maps domain exceptions to safe HTTP outcomes. Honey-token trips look like an
/// ordinary sign-out + not-found to the attacker; audit failures surface as a 503
/// so callers know the vault chose fail-closed over fail-open.
/// </summary>
public sealed class GlobalExceptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<GlobalExceptionMiddleware> _logger;

    public GlobalExceptionMiddleware(RequestDelegate next, ILogger<GlobalExceptionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (HoneyTokenTrippedException ex) when (!context.Response.HasStarted)
        {
            // Intrusion response already executed inside the service layer.
            _logger.LogWarning("Honey-token {SecretName} tripped during {Path}; terminating session", ex.SecretName, context.Request.Path);
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            context.Response.Redirect("/Account/Login");
        }
        catch (AuditWriteFailedException ex) when (!context.Response.HasStarted)
        {
            _logger.LogCritical(ex, "Fail-closed: request to {Path} aborted because the audit trail is unavailable", context.Request.Path);
            context.Response.Redirect("/Home/Error?code=503");
        }
        catch (SecretNotFoundException ex) when (!context.Response.HasStarted)
        {
            _logger.LogInformation("Secret {SecretId} not found for {Path}", ex.SecretId, context.Request.Path);
            context.Response.Redirect("/Home/Error?code=404");
        }
        catch (CryptoConfigurationException ex) when (!context.Response.HasStarted)
        {
            _logger.LogCritical(ex, "Cryptographic subsystem misconfiguration surfaced during {Path}", context.Request.Path);
            context.Response.Redirect("/Home/Error?code=500");
        }
        catch (DomainException ex) when (!context.Response.HasStarted)
        {
            _logger.LogError(ex, "Domain error during {Path}", context.Request.Path);
            context.Response.Redirect("/Home/Error?code=400");
        }
        catch (Exception ex) when (!context.Response.HasStarted)
        {
            _logger.LogError(ex, "Unhandled exception during {Path}", context.Request.Path);
            context.Response.Redirect("/Home/Error?code=500");
        }
    }
}
