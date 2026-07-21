namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Records that a premium (Max-only) feature was exercised. Implementations are soft: when the
/// current license already grants the feature they do nothing; otherwise they surface a single
/// deduplicated audit line and return. They never throw and never change the caller's behaviour —
/// licensing must never block the vault.
/// </summary>
public interface IPremiumFeatureUsage
{
    /// <summary>
    /// Note a use of <paramref name="featureKey"/> (a <c>LicenseFeatures</c> constant). A no-op when
    /// the feature is licensed; otherwise records one soft audit line per feature per process.
    /// </summary>
    Task RecordUseAsync(string featureKey, CancellationToken ct);
}
