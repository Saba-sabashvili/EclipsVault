using System.Security.Cryptography;
using System.Text;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using Xunit;

namespace EclipsVault.Tests.Licensing;

public class LicenseVerifierTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

    private static LicenseClaims Claims(DateTimeOffset? notAfter) => new(
        "lic-1", LicenseTier.Max, "Acme Ltd", "ops@acme.example",
        new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), notAfter, null, 3, []);

    /// <summary>
    /// A build with no vendor key pinned must stay soft rather than throwing — an unconfigured vendor
    /// key is the vendor's problem and must never become the operator's outage. Note this passes an
    /// explicitly empty key rather than reading the pinned one: written when the pinned key really was
    /// empty, it would have quietly stopped testing anything the moment a key was set.
    /// </summary>
    [Fact]
    public void An_unset_vendor_key_refuses_every_licence_without_throwing()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = LicenseSigner.Sign(Claims(Now.AddYears(1)), key);

        var result = LicenseVerifier.Verify(token, [], Now);

        Assert.Equal(LicenseStatus.InvalidSignature, result.Status);
    }

    /// <summary>
    /// The pinned vendor key must be a usable P-256 public key. A truncated or mangled paste would
    /// otherwise ship silently: every licence would verify as InvalidSignature, soft enforcement would
    /// keep the vault running, and the first evidence of the mistake would be a paying customer whose
    /// vault says "unlicensed". This costs nothing and closes exactly that gap.
    /// </summary>
    [Fact]
    public void The_pinned_vendor_key_is_a_usable_P256_public_key()
    {
        Assert.NotEmpty(LicensePublicKey.Spki);

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(LicensePublicKey.Spki, out var bytesRead);

        Assert.Equal(LicensePublicKey.Spki.Length, bytesRead);
        Assert.Equal(256, ecdsa.KeySize);
    }

    /// <summary>
    /// A licence signed by anyone other than the vendor must not verify against the pinned key. This
    /// is the property the whole licensing scheme rests on, asserted against the real shipped key.
    /// </summary>
    [Fact]
    public void A_licence_signed_by_a_stranger_is_refused_by_the_pinned_key()
    {
        using var impostor = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var forged = LicenseSigner.Sign(Claims(Now.AddYears(1)), impostor);

        var result = LicenseVerifier.Verify(forged, LicensePublicKey.Spki, Now);

        Assert.Equal(LicenseStatus.InvalidSignature, result.Status);
    }

    [Fact]
    public void A_correctly_signed_unexpired_token_is_valid()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = LicenseSigner.Sign(Claims(Now.AddYears(1)), key);

        var result = LicenseVerifier.Verify(token, key.ExportSubjectPublicKeyInfo(), Now);

        Assert.Equal(LicenseStatus.Valid, result.Status);
        Assert.Equal("Acme Ltd", result.Claims!.IssuedTo);
    }

    [Fact]
    public void A_null_or_empty_token_is_missing()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var result = LicenseVerifier.Verify(null, key.ExportSubjectPublicKeyInfo(), Now);
        Assert.Equal(LicenseStatus.Missing, result.Status);
    }

    [Fact]
    public void Garbage_is_malformed()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var result = LicenseVerifier.Verify("EVLIC1.not.base64url!!", key.ExportSubjectPublicKeyInfo(), Now);
        Assert.Equal(LicenseStatus.Malformed, result.Status);
    }

    [Fact]
    public void A_token_signed_by_a_different_key_fails_signature()
    {
        using var vendor = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var attacker = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = LicenseSigner.Sign(Claims(Now.AddYears(1)), attacker);

        var result = LicenseVerifier.Verify(token, vendor.ExportSubjectPublicKeyInfo(), Now);

        Assert.Equal(LicenseStatus.InvalidSignature, result.Status);
        Assert.Null(result.Claims); // untrusted — do not surface claims
    }

    [Fact]
    public void An_expired_but_correctly_signed_token_is_expired_and_still_surfaces_claims()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = LicenseSigner.Sign(Claims(Now.AddDays(-1)), key);

        var result = LicenseVerifier.Verify(token, key.ExportSubjectPublicKeyInfo(), Now);

        Assert.Equal(LicenseStatus.Expired, result.Status);
        Assert.Equal("Acme Ltd", result.Claims!.IssuedTo);
    }

    [Theory]
    [InlineData("9000000000000000000", "-", "-")] // issuedAt ticks parse as long but exceed DateTime range
    [InlineData("0", "9000000000000000000", "-")]  // notAfter ticks parse as long but exceed DateTime range
    [InlineData("0", "-", "9000000000000000000")]  // updatesUntil ticks parse as long but exceed DateTime range
    public void A_token_with_out_of_range_ticks_is_malformed_not_a_crash(string issuedTicks, string notAfterTicks, string updatesUntilTicks)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // A structurally valid payload whose tick fields parse as a long but fall outside the
        // DateTime tick range. TryDeserialize runs before the signature check, so if it constructs
        // a DateTimeOffset from these unguarded it throws — and Verify is contractually throw-proof.
        const char sep = '';
        var issuedTo = Convert.ToBase64String(Encoding.UTF8.GetBytes("Acme Ltd"));
        var payloadText = string.Join(sep,
            "lic-1", ((int)LicenseTier.Max).ToString(), issuedTo, "",
            issuedTicks, notAfterTicks, "3", "", updatesUntilTicks);
        var payload = Encoding.UTF8.GetBytes(payloadText);
        var signature = key.SignData(payload, HashAlgorithmName.SHA256);
        var token = LicenseToken.Encode(payload, signature);

        var result = LicenseVerifier.Verify(token, key.ExportSubjectPublicKeyInfo(), Now);

        Assert.Equal(LicenseStatus.Malformed, result.Status);
    }

    [Fact]
    public void A_tampered_payload_fails_signature()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = LicenseSigner.Sign(Claims(Now.AddYears(1)), key);

        // Flip a character in the payload segment.
        var parts = token.Split('.');
        var body = parts[1].ToCharArray();
        body[0] = body[0] == 'A' ? 'B' : 'A';
        var tampered = $"{parts[0]}.{new string(body)}.{parts[2]}";

        var result = LicenseVerifier.Verify(tampered, key.ExportSubjectPublicKeyInfo(), Now);
        Assert.True(result.Status is LicenseStatus.InvalidSignature or LicenseStatus.Malformed);
    }
}
