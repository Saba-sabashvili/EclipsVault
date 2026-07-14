using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Snapshot of a secret as it may be cached: attribute metadata plus the encrypted
/// envelope. Decrypted material is NEVER placed in the cache.
/// </summary>
public sealed record EncryptedSecretEnvelope(
    Guid Id,
    string Name,
    string ProjectKey,
    SecretEnvironment Environment,
    SensitivityLevel Sensitivity,
    byte[] Ciphertext,
    byte[] WrappedDek,
    string KekId,
    string Algorithm,
    bool IsHoneyToken,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? UpdatedAtUtc,
    DateTimeOffset? ExpiresAtUtc);

/// <summary>
/// Cache-aside store for encrypted envelopes. Entries carry a short absolute TTL and
/// are evicted eagerly by the service layer on every write/update/delete. Backed by a
/// shared store (Redis) in multi-node deployments so a write on one node evicts the
/// stale envelope for every node; single-node deployments use an in-process cache.
/// </summary>
public interface ISecretCache
{
    Task<EncryptedSecretEnvelope?> GetAsync(Guid secretId, CancellationToken ct = default);

    Task SetAsync(EncryptedSecretEnvelope envelope, CancellationToken ct = default);

    Task EvictAsync(Guid secretId, CancellationToken ct = default);
}
