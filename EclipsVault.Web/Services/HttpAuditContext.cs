using EclipsVault.Web.Extensions;

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

    public Guid? UserId => _accessor.HttpContext?.User.GetUserIdOrNull();

    public string? Username => _accessor.HttpContext?.User.Identity?.Name;

    public string? SourceIp => _accessor.HttpContext?.Connection.RemoteIpAddress?.ToString();
}
