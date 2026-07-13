namespace EclipsVault.Core.Application.KeyManagement;

/// <summary>How many stored items are wrapped under a given KEK.</summary>
public sealed record KekUsage(string KekId, bool IsCurrent, bool IsKnown, int SecretCount, int VersionCount)
{
    public int Total => SecretCount + VersionCount;
}

/// <summary>Snapshot of the key-encryption-key estate for the admin Encryption page.</summary>
public sealed record KekStatus(
    string CurrentKekId,
    IReadOnlyList<string> KnownKekIds,
    IReadOnlyList<KekUsage> Usage)
{
    /// <summary>Items still wrapped under a KEK other than the current one (i.e. awaiting rotation).</summary>
    public int PendingRewrap => Usage.Where(u => !u.IsCurrent).Sum(u => u.Total);
}

/// <summary>Outcome of a rotation pass.</summary>
public sealed record KekRotationResult(string CurrentKekId, int SecretsRewrapped, int VersionsRewrapped);

/// <summary>
/// Key lifecycle management. Rotation re-wraps every secret's (and archived version's) data-encryption
/// key under the <em>current</em> master KEK and retires the old one — the payload ciphertext never
/// changes. The operator supplies the new current KEK and keeps the previous key available as a retired
/// key (so existing DEKs can still be unwrapped) until rotation completes; afterwards the old key can be
/// removed. Aligns with NIST 800-57 cryptoperiods and PCI-DSS 3.6/3.7.
/// </summary>
public interface IKekRotationService
{
    Task<KekStatus> GetStatusAsync(CancellationToken ct);

    Task<KekRotationResult> RotateAsync(CancellationToken ct);
}
