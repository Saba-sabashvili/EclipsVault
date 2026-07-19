using System.Security.Cryptography;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using Xunit;

namespace EclipsVault.Tests.Licensing;

public class LicenseTokenTests
{
    private static LicenseClaims Sample() => new(
        LicenseId: "9f1c2d3e",
        Tier: LicenseTier.Max,
        IssuedTo: "Acme Ltd — Ünïcode & separators\tok",
        Contact: "ops@acme.example",
        IssuedAtUtc: new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
        NotAfterUtc: new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
        UpdatesUntilUtc: new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero),
        MaxNodes: 3,
        Features: []);

    [Fact]
    public void Canonical_round_trips_every_field()
    {
        var claims = Sample();
        var bytes = LicenseCanonical.Serialize(claims);

        Assert.True(LicenseCanonical.TryDeserialize(bytes, out var back));
        Assert.NotNull(back);
        Assert.Equal(claims.LicenseId, back!.LicenseId);
        Assert.Equal(claims.Tier, back.Tier);
        Assert.Equal(claims.IssuedTo, back.IssuedTo);
        Assert.Equal(claims.Contact, back.Contact);
        Assert.Equal(claims.IssuedAtUtc, back.IssuedAtUtc);
        Assert.Equal(claims.NotAfterUtc, back.NotAfterUtc);
        Assert.Equal(claims.UpdatesUntilUtc, back.UpdatesUntilUtc);
        Assert.Equal(claims.MaxNodes, back.MaxNodes);
    }

    [Fact]
    public void Token_encodes_and_decodes_the_exact_bytes()
    {
        byte[] payload = [1, 2, 3, 250, 0, 99];
        byte[] sig = [9, 8, 7];

        var token = LicenseToken.Encode(payload, sig);
        Assert.StartsWith("EVLIC1.", token);

        Assert.True(LicenseToken.TryDecode(token, out var p, out var s));
        Assert.Equal(payload, p);
        Assert.Equal(sig, s);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-token")]
    [InlineData("WRONG.aaaa.bbbb")]
    [InlineData("EVLIC1.only-two-parts")]
    [InlineData("EVLIC1.!!!notbase64!!!.bbbb")]
    public void Token_decode_rejects_malformed_input(string? token)
    {
        Assert.False(LicenseToken.TryDecode(token, out _, out _));
    }

    [Fact]
    public void Signer_produces_a_token_whose_signature_matches_the_canonical_payload()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = LicenseSigner.Sign(Sample(), key);

        Assert.True(LicenseToken.TryDecode(token, out var payload, out var sig));
        Assert.True(key.VerifyData(payload, sig, HashAlgorithmName.SHA256));
    }
}
