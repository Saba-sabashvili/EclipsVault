using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// One issued dynamic credential, tracked from mint to destruction.
///
/// Deliberately holds no password. The secret is shown once at issue and never again — the vault
/// keeps only what it needs to revoke the credential later (which backend, and under what name), so
/// a lease table leak yields no live credentials.
/// </summary>
public class DynamicSecretLease
{
    public Guid Id { get; set; }

    public Guid RoleId { get; set; }

    /// <summary>Snapshot of the role's name, so a lease stays readable after the role changes.</summary>
    public string RoleName { get; set; } = string.Empty;

    /// <summary>The vault user who took the credential out.</summary>
    public Guid UserId { get; set; }

    public string Username { get; set; } = string.Empty;

    /// <summary>The minted principal's name on the backend — the handle revocation needs.</summary>
    public string CredentialIdentity { get; set; } = string.Empty;

    public DateTimeOffset IssuedAtUtc { get; set; }

    /// <summary>When the reaper destroys the credential, unless it is handed back first.</summary>
    public DateTimeOffset ExpiresAtUtc { get; set; }

    /// <summary>When the lease actually ended (revoked, expired, or failed to revoke).</summary>
    public DateTimeOffset? ClosedAtUtc { get; set; }

    public LeaseStatus Status { get; set; } = LeaseStatus.Active;

    /// <summary>Why the backend refused to destroy the credential, when <see cref="Status"/> says so.</summary>
    public string? RevocationError { get; set; }

    /// <summary>True once the TTL has elapsed and the credential is due for destruction.</summary>
    public bool IsDue(DateTimeOffset nowUtc) => Status == LeaseStatus.Active && ExpiresAtUtc <= nowUtc;

    /// <summary>Closes the lease after the backend destroyed the credential.</summary>
    public void Close(LeaseStatus status, DateTimeOffset nowUtc, string? error = null)
    {
        Status = status;
        ClosedAtUtc = nowUtc;
        RevocationError = error;
    }
}
