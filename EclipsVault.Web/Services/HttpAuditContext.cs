using System.Security.Claims;

namespace EclipsVault.Web.Services;

/// <summary>
/// Resolves the current actor from the HTTP request. Outside a request (seeder,
/// background worker scopes) every member returns null, which the audit pipeline
/// records as the "system" actor.
/// </summary>
public sealed class HttpAuditContext : IAuditContext
{
    private readonly IHttpContextAccessor _accessor;

    public HttpAuditContext(IHttpContextAccessor accessor) => _accessor = accessor;

    public Guid? UserId
        => Guid.TryParse(_accessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier), out var id)
            ? id
            : null;

    public string? Username => _accessor.HttpContext?.User.Identity?.Name;

    public string? SourceIp => _accessor.HttpContext?.Connection.RemoteIpAddress?.ToString();
}
