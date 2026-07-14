using EclipsVault.Infrastructure.Security;
using Xunit;

namespace EclipsVault.Tests.Security;

public class VaultTransitFormatTests
{
    [Theory]
    [InlineData("vault:v1:Zm9vYmFy", "vault:eclipsvault:v1")]
    [InlineData("vault:v42:abcdef", "vault:eclipsvault:v42")]
    public void KekId_surfaces_the_wrapping_key_version(string ciphertext, string expected)
        => Assert.Equal(expected, VaultTransitFormat.KekId("eclipsvault", ciphertext));

    [Fact]
    public void KekId_honours_the_configured_key_name()
        => Assert.Equal("vault:prod-master:v3", VaultTransitFormat.KekId("prod-master", "vault:v3:abc"));

    [Fact]
    public void KekId_is_defensive_against_a_malformed_ciphertext()
        => Assert.Equal("vault:eclipsvault:v?", VaultTransitFormat.KekId("eclipsvault", "garbage"));
}
