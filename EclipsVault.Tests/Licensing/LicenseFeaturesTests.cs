using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using Xunit;

namespace EclipsVault.Tests.Licensing;

public class LicenseFeaturesTests
{
    private static LicenseClaims Claims(LicenseTier tier, params string[] features)
        => new("lic-1", tier, "Acme Ltd", null,
               DateTimeOffset.UnixEpoch, null, 0, features);

    [Fact]
    public void Community_grants_no_premium_features()
    {
        var effective = LicenseTierFeatures.Effective(Claims(LicenseTier.Community));
        Assert.Empty(effective);
    }

    [Fact]
    public void Pro_grants_the_operational_features_not_the_enterprise_ones()
    {
        var effective = LicenseTierFeatures.Effective(Claims(LicenseTier.Pro));
        Assert.Contains(LicenseFeatures.Sso, effective);
        Assert.Contains(LicenseFeatures.Kms, effective);
        Assert.Contains(LicenseFeatures.RedisHa, effective);
        Assert.Contains(LicenseFeatures.DynamicSecrets, effective);
        Assert.DoesNotContain(LicenseFeatures.ManagedRotation, effective);
        Assert.DoesNotContain(LicenseFeatures.AuditAttestation, effective);
    }

    [Fact]
    public void Enterprise_grants_everything_pro_has_plus_the_enterprise_features()
    {
        var effective = LicenseTierFeatures.Effective(Claims(LicenseTier.Enterprise));
        Assert.Contains(LicenseFeatures.Sso, effective);
        Assert.Contains(LicenseFeatures.ManagedRotation, effective);
        Assert.Contains(LicenseFeatures.AuditAttestation, effective);
    }

    [Fact]
    public void Explicit_features_on_the_claim_override_the_tier_default()
    {
        // A bespoke Community license that was sold one extra feature.
        var effective = LicenseTierFeatures.Effective(Claims(LicenseTier.Community, LicenseFeatures.Kms));
        Assert.Equal(new[] { LicenseFeatures.Kms }, effective);
    }
}
