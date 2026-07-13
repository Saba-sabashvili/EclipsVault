using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Abstractions;

/// <summary>Convenience writers over <see cref="IAuditSink"/> for the recurring audit shapes.</summary>
public static class AuditSinkExtensions
{
    /// <summary>
    /// Writes a User-scoped audit entry where the acting user is also the subject — the shape
    /// shared by the authentication, self-service profile, and admin user services. Centralising
    /// it here keeps the <see cref="AuditEntry"/> field mapping in one place.
    /// </summary>
    public static Task WriteUserEventAsync(
        this IAuditSink audit, AuditAction action, Guid? userId, string username, string? details, CancellationToken ct)
        => audit.WriteAsync(new AuditEntry
        {
            Action = action,
            ResourceType = "User",
            ResourceId = userId,
            ActorUserId = userId,
            ActorUsername = username,
            Details = details
        }, ct);
}
