using EclipsVault.Core.Application.Licensing;
using EclipsVault.Infrastructure.Distributed;
using EclipsVault.Infrastructure.Security;
using EclipsVault.Infrastructure.Security.Licensing;
using Microsoft.Extensions.Options;
using Xunit;

namespace EclipsVault.Tests.Licensing;

public class ConfiguredPremiumFeaturesTests
{
    private static ConfiguredPremiumFeatures Build(string engine, bool redis, string ssoAuthority)
        => new(
            Options.Create(new CryptoOptions { Engine = engine }),
            Options.Create(new RedisOptions { Enabled = redis }),
            Options.Create(new SsoOptions { Authority = ssoAuthority }));

    [Fact]
    public void Nothing_configured_is_empty()
        => Assert.Empty(Build(AesGcmCryptoEngine.EngineName, redis: false, ssoAuthority: "").Active);

    [Fact]
    public void VaultTransit_engine_activates_kms()
    {
        var active = Build(VaultTransitCryptoEngine.EngineName, redis: false, ssoAuthority: "").Active;
        Assert.Contains(LicenseFeatures.Kms, active);
        Assert.DoesNotContain(LicenseFeatures.RedisHa, active);
    }

    [Fact]
    public void Redis_enabled_activates_redis_ha()
        => Assert.Contains(LicenseFeatures.RedisHa, Build(AesGcmCryptoEngine.EngineName, redis: true, ssoAuthority: "").Active);

    [Fact]
    public void Sso_authority_activates_sso()
        => Assert.Contains(LicenseFeatures.Sso, Build(AesGcmCryptoEngine.EngineName, redis: false, ssoAuthority: "https://idp.example").Active);

    [Fact]
    public void All_three_configured_are_all_present()
    {
        var active = Build(VaultTransitCryptoEngine.EngineName, redis: true, ssoAuthority: "https://idp.example").Active;
        Assert.Equal(
            new HashSet<string> { LicenseFeatures.Kms, LicenseFeatures.RedisHa, LicenseFeatures.Sso },
            active);
    }
}
