namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Records — and, for gated features, enforces — use of a premium (Max-only) feature.
/// <see cref="RecordUseAsync"/> is soft and never throws; <see cref="RequireAsync"/> additionally
/// refuses a gated feature when the license does not grant it. Licensing must never block the vault
/// beyond that deliberate, gated refusal.
/// </summary>
public interface IPremiumFeatureUsage
{
    /// <summary>
    /// Note a use of <paramref name="featureKey"/> (a <c>LicenseFeatures</c> constant). A no-op when
    /// the feature is licensed; otherwise records one soft audit line per feature per process. Never throws.
    /// </summary>
    Task RecordUseAsync(string featureKey, CancellationToken ct);

    /// <summary>
    /// Require a license for <paramref name="featureKey"/> before the caller proceeds. Licensed: a
    /// no-op. Unlicensed and <see cref="Licensing.LicenseFeatures.Gated">gated</see>: records one
    /// deduplicated <c>LicenseFeatureBlocked</c> audit line and throws
    /// <see cref="Domain.Exceptions.PremiumFeatureNotLicensedException"/> on every call. Unlicensed and
    /// not gated: behaves exactly like <see cref="RecordUseAsync"/>.
    /// </summary>
    Task RequireAsync(string featureKey, CancellationToken ct);
}
