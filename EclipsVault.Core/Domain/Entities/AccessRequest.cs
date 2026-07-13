using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// A user's request for access to a secret the ABAC policy denied them. A reviewer
/// (an administrator, or a member of the secret's project) approves it — which creates
/// an ordinary <see cref="SecretGrant"/> — or rejects it. Secret name, project, and the
/// denial reasons are snapshotted so the queue reads without extra joins and the reviewer
/// can see exactly what was refused.
/// </summary>
public class AccessRequest
{
    public Guid Id { get; set; }

    public Guid SecretId { get; set; }

    /// <summary>Denormalized for display without a join (the FK still guarantees the secret exists).</summary>
    public string SecretName { get; set; } = string.Empty;

    /// <summary>The secret's project, used to route the request to that project's reviewers.</summary>
    public string ProjectKey { get; set; } = string.Empty;

    public Guid RequesterUserId { get; set; }

    public string RequesterUsername { get; set; } = string.Empty;

    /// <summary>The requester's justification.</summary>
    public string Reason { get; set; } = string.Empty;

    /// <summary>Snapshot of the ABAC denial reasons at request time, so reviewers see what failed.</summary>
    public string? DeniedReasons { get; set; }

    public AccessRequestStatus Status { get; set; } = AccessRequestStatus.Pending;

    public DateTimeOffset CreatedAtUtc { get; set; }

    public DateTimeOffset? DecidedAtUtc { get; set; }

    /// <summary>Username of the reviewer who approved or rejected.</summary>
    public string? DecidedBy { get; set; }

    public string? DecisionNote { get; set; }
}
