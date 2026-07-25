using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using EclipsVault.Infrastructure.Security.WebAuthn;
using Xunit;

namespace EclipsVault.Tests.Security;

/// <summary>
/// Registration parses attacker-supplied bytes: an attestation object arrives from the browser and
/// is decoded before anything about it has been proven. Every malformed shape must therefore come
/// back as a <see cref="WebAuthnException"/> — a clean refusal — rather than escaping as whatever
/// the CBOR reader happened to throw, which would surface as a 500 and read like a broken vault.
/// </summary>
public class WebAuthnVerifierTests
{
    private const string RpId = "vault.example.com";

    private const byte FlagUserPresent = 0x01;
    private const byte FlagUserVerified = 0x04;
    private const byte FlagAttestedCredentialData = 0x40;

    /// <summary>
    /// authData: rpIdHash(32) | flags(1) | signCount(4) | aaguid(16) | credIdLen(2) | credId | COSE key.
    /// </summary>
    private static byte[] AuthData(byte[] coseKey, byte flags = FlagUserPresent | FlagUserVerified | FlagAttestedCredentialData)
    {
        var credId = new byte[16];
        RandomNumberGenerator.Fill(credId);

        var buffer = new List<byte>();
        buffer.AddRange(SHA256.HashData(Encoding.UTF8.GetBytes(RpId)));
        buffer.Add(flags);
        buffer.AddRange(new byte[] { 0, 0, 0, 1 });      // signCount
        buffer.AddRange(new byte[16]);                    // aaguid
        buffer.AddRange([(byte)(credId.Length >> 8), (byte)(credId.Length & 0xFF)]);
        buffer.AddRange(credId);
        buffer.AddRange(coseKey);
        return [.. buffer];
    }

    private static byte[] AttestationObject(byte[] authData)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt");
        writer.WriteTextString("none");
        writer.WriteTextString("attStmt");
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteTextString("authData");
        writer.WriteByteString(authData);
        writer.WriteEndMap();
        return writer.Encode();
    }

    [Fact]
    public void An_absent_credential_public_key_is_refused_cleanly()
    {
        // Everything up to the COSE key is well formed; the key itself is simply not there.
        var attestation = AttestationObject(AuthData(coseKey: []));

        Assert.Throws<WebAuthnException>(
            () => WebAuthnVerifier.ParseAttestation(attestation, RpId, requireUserVerification: true));
    }

    [Fact]
    public void A_truncated_credential_public_key_is_refused_cleanly()
    {
        // 0xA5 opens a 5-entry CBOR map that never arrives.
        var attestation = AttestationObject(AuthData(coseKey: [0xA5]));

        Assert.Throws<WebAuthnException>(
            () => WebAuthnVerifier.ParseAttestation(attestation, RpId, requireUserVerification: true));
    }

    [Fact]
    public void A_mismatched_relying_party_is_refused()
    {
        var attestation = AttestationObject(AuthData(coseKey: []));

        Assert.Throws<WebAuthnException>(
            () => WebAuthnVerifier.ParseAttestation(attestation, "attacker.example", requireUserVerification: true));
    }

    [Fact]
    public void An_authenticator_that_did_not_verify_the_user_is_refused_when_uv_is_required()
    {
        var attestation = AttestationObject(
            AuthData(coseKey: [], flags: FlagUserPresent | FlagAttestedCredentialData));

        Assert.Throws<WebAuthnException>(
            () => WebAuthnVerifier.ParseAttestation(attestation, RpId, requireUserVerification: true));
    }

    [Fact]
    public void Authenticator_data_that_is_too_short_is_refused()
    {
        var attestation = AttestationObject(new byte[10]);

        Assert.Throws<WebAuthnException>(
            () => WebAuthnVerifier.ParseAttestation(attestation, RpId, requireUserVerification: true));
    }

    [Fact]
    public void A_malformed_attestation_object_is_refused()
        => Assert.Throws<WebAuthnException>(
            () => WebAuthnVerifier.ParseAttestation([0xFF, 0xFF, 0xFF], RpId, requireUserVerification: true));
}
