using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// One entry to append to the immutable audit trail. The actor (who did it) and the
/// source IP are supplied by the sink from the ambient request context; only when
/// there is no authenticated principal yet — an in-flight login — does a caller
/// override the actor with the subject being authenticated.
/// </summary>
public sealed record AuditEntry
{
    public required AuditAction Action { get; init; }

    public required string ResourceType { get; init; }

    public Guid? ResourceId { get; init; }

    public string? ResourceName { get; init; }

    public string? Details { get; init; }

    public bool IsCritical { get; init; }

    /// <summary>Overrides the recorded actor id (used for auth events with no authenticated principal).</summary>
    public Guid? ActorUserId { get; init; }

    /// <summary>Overrides the recorded actor name (used for auth events with no authenticated principal).</summary>
    public string? ActorUsername { get; init; }
}

/// <summary>
/// Fail-closed writer for the immutable audit trail — the single place audit rows are
/// created. Implementations MUST throw <c>AuditWriteFailedException</c> when the entry
/// cannot be persisted, so the calling operation aborts before any secret material is
/// released.
/// </summary>
public interface IAuditSink
{
    Task WriteAsync(AuditEntry entry, CancellationToken ct);
}
