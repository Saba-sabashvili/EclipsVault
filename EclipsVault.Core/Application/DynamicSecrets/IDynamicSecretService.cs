using EclipsVault.Core.Domain.Entities;

namespace EclipsVault.Core.Application.DynamicSecrets;

/// <summary>
/// Issues and reclaims short-lived backend credentials.
///
/// The vault stores no value for these: it mints one on request, hands it over once, and destroys
/// it when the lease ends. ABAC gating is the caller's job (the handler runs on the role, which is
/// an <see cref="Abac.IAbacResource"/>) — this service owns the lease lifecycle.
/// </summary>
public interface IDynamicSecretService
{
    Task<IReadOnlyList<DynamicSecretRoleDto>> ListRolesAsync(CancellationToken ct);

    Task<DynamicSecretRoleDto?> FindRoleAsync(Guid roleId, CancellationToken ct);

    /// <summary>
    /// Mints a credential and opens a lease. <paramref name="ttlMinutes"/> is clamped to the role's
    /// ceiling; null takes the role's default. The returned secret is never retrievable again.
    /// </summary>
    Task<IssuedCredentialDto> IssueAsync(Guid roleId, int? ttlMinutes, CancellationToken ct);

    Task<IReadOnlyList<LeaseDto>> ListLeasesAsync(Guid userId, bool includeEveryone, CancellationToken ct);

    /// <summary>
    /// Hands a credential back early. A caller may only revoke their own lease unless
    /// <paramref name="isAdmin"/>. Returns false when the lease is unknown, already closed, or
    /// someone else's — indistinguishable on purpose, so this cannot be used to probe for leases.
    /// </summary>
    Task<bool> RevokeAsync(Guid leaseId, Guid userId, bool isAdmin, CancellationToken ct);

    /// <summary>Destroys every credential whose lease has elapsed. Returns how many were closed.</summary>
    Task<int> ReapDueLeasesAsync(CancellationToken ct);

    /// <summary>The role behind a lease, for re-checking access before revoking.</summary>
    Task<DynamicSecretLease?> FindLeaseAsync(Guid leaseId, CancellationToken ct);
}
