using EclipsVault.Core.Domain.Entities;

namespace EclipsVault.Core.Application.Secrets;

/// <summary>
/// Persistence boundary for secrets. Write operations that must be audited atomically
/// with the change (create/update/shred) are audited by the SaveChanges interceptor;
/// read/share auditing is written separately through <see cref="IAuditSink"/>.
/// </summary>
public interface ISecretRepository
{
    Task<Secret?> FindAsync(Guid id, CancellationToken ct);

    Task<IReadOnlyList<Secret>> ListActiveAsync(DateTimeOffset asOfUtc, CancellationToken ct);

    Task<IReadOnlyList<Secret>> ListExpiredAsync(DateTimeOffset asOfUtc, CancellationToken ct);

    /// <summary>
    /// Live secrets whose deadline falls between now and <paramref name="horizonUtc"/> and that have
    /// not yet been warned about that deadline — the candidates for an expiry notice.
    /// </summary>
    Task<IReadOnlyList<Secret>> ListExpiringAsync(DateTimeOffset asOfUtc, DateTimeOffset horizonUtc, CancellationToken ct);

    /// <summary>
    /// Records that an expiry notice has been sent for the secret's current deadline, writing that
    /// column and nothing else. Distinct from <see cref="UpdateAsync"/> on purpose: this is
    /// bookkeeping, and a whole-entity update would be indistinguishable from a real edit — and so
    /// audited as one, telling an auditor a secret was modified that nobody touched.
    /// </summary>
    Task MarkExpiryNoticeSentAsync(Secret secret, CancellationToken ct);

    Task AddAsync(Secret secret, CancellationToken ct);

    Task UpdateAsync(Secret secret, CancellationToken ct);

    Task DeleteAsync(Secret secret, CancellationToken ct);

    /// <summary>Persists a rotation: inserts the archived version and updates the secret in one transaction.</summary>
    Task RotateAsync(Secret secret, SecretVersion archivedVersion, CancellationToken ct);

    /// <summary>Shreds the secret and purges its archived versions (which hold key material) in one transaction.</summary>
    Task ShredAsync(Secret secret, CancellationToken ct);

    Task<IReadOnlyList<SecretVersion>> ListVersionsAsync(Guid secretId, CancellationToken ct);

    Task<SecretVersion?> FindVersionAsync(Guid secretId, Guid versionId, CancellationToken ct);

    Task<int> CountVersionsAsync(Guid secretId, CancellationToken ct);
}
