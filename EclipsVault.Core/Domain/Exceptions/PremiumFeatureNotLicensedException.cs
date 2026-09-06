namespace EclipsVault.Core.Domain.Exceptions;

/// <summary>
/// Raised when a gated premium feature is used without a licence that grants it. It is a payment /
/// entitlement boundary, not a fault: the operation is refused cleanly and nothing at rest is touched.
/// The Web layer maps it to 402 Payment Required.
/// </summary>
public sealed class PremiumFeatureNotLicensedException : DomainException
{
    public PremiumFeatureNotLicensedException(string featureKey)
        : base($"The '{featureKey}' feature requires a licence.")
        => FeatureKey = featureKey;

    /// <summary>The <c>LicenseFeatures</c> key that was refused.</summary>
    public string FeatureKey { get; }
}
