using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;

namespace EclipsVault.Infrastructure.Security.WebAuthn;

/// <summary>Raised when a WebAuthn response fails verification. The message is caller-safe (no secrets).</summary>
public sealed class WebAuthnException : Exception
{
    public WebAuthnException(string message) : base(message) { }
}

/// <summary>A credential extracted from an attestation object during registration.</summary>
public readonly record struct AttestedCredential(byte[] CredentialId, byte[] CosePublicKey, uint SignCount);

/// <summary>
/// Server-side verification of WebAuthn attestation (registration) and assertion (sign-in)
/// responses, per the W3C Web Authentication spec. Attestation is accepted in "none" format —
/// the enrollment happens inside an already-authenticated session, so the vault trusts the
/// binding without a separate attestation-statement chain. User presence is always required
/// and user verification is enforced, giving each passkey the "something you have + something
/// you are/know" property that makes it a self-contained second factor.
/// </summary>
public static class WebAuthnVerifier
{
    private const byte FlagUserPresent = 0x01;
    private const byte FlagUserVerified = 0x04;
    private const byte FlagAttestedCredentialData = 0x40;

    /// <summary>Parses and validates an attestation object, returning the new credential to store.</summary>
    public static AttestedCredential ParseAttestation(byte[] attestationObject, string rpId, bool requireUserVerification)
    {
        byte[]? authData = null;
        try
        {
            var reader = new CborReader(attestationObject, CborConformanceMode.Lax);
            var count = reader.ReadStartMap() ?? throw new WebAuthnException("Attestation object is not a definite-length map.");
            for (var i = 0; i < count; i++)
            {
                var key = reader.ReadTextString();
                if (key == "authData")
                {
                    authData = reader.ReadByteString();
                }
                else
                {
                    reader.SkipValue();
                }
            }

            reader.ReadEndMap();
        }
        catch (CborContentException)
        {
            throw new WebAuthnException("Malformed attestation object.");
        }
        catch (InvalidOperationException)
        {
            throw new WebAuthnException("Malformed attestation object.");
        }

        if (authData is null)
        {
            throw new WebAuthnException("Attestation object is missing authenticator data.");
        }

        ValidateRpIdHashAndFlags(authData, rpId, requireUserVerification, out var attested);
        if (!attested)
        {
            throw new WebAuthnException("Authenticator did not return attested credential data.");
        }

        var signCount = BinaryPrimitives.ReadUInt32BigEndian(authData.AsSpan(33, 4));

        // Attested credential data layout: aaguid(16) | credIdLen(2) | credId | COSE public key.
        const int attestedStart = 37;
        if (authData.Length < attestedStart + 18)
        {
            throw new WebAuthnException("Attested credential data is truncated.");
        }

        var credIdLen = BinaryPrimitives.ReadUInt16BigEndian(authData.AsSpan(attestedStart + 16, 2));
        var credIdStart = attestedStart + 18;
        if (authData.Length < credIdStart + credIdLen)
        {
            throw new WebAuthnException("Credential id is truncated.");
        }

        var credentialId = authData.AsSpan(credIdStart, credIdLen).ToArray();

        var coseKey = ReadSingleCborItem(authData.AsMemory(credIdStart + credIdLen));
        CoseKey.Validate(coseKey);

        return new AttestedCredential(credentialId, coseKey, signCount);
    }

    /// <summary>
    /// Verifies an assertion signature against a stored COSE public key and returns the
    /// authenticator's new signature counter (for clone detection by the caller).
    /// </summary>
    public static uint VerifyAssertion(
        byte[] authenticatorData,
        byte[] clientDataJson,
        byte[] signature,
        byte[] cosePublicKey,
        string rpId,
        bool requireUserVerification)
    {
        ValidateRpIdHashAndFlags(authenticatorData, rpId, requireUserVerification, out _);
        var signCount = BinaryPrimitives.ReadUInt32BigEndian(authenticatorData.AsSpan(33, 4));

        // The signature covers authenticatorData || SHA-256(clientDataJSON).
        var clientHash = SHA256.HashData(clientDataJson);
        var signedData = new byte[authenticatorData.Length + clientHash.Length];
        Buffer.BlockCopy(authenticatorData, 0, signedData, 0, authenticatorData.Length);
        Buffer.BlockCopy(clientHash, 0, signedData, authenticatorData.Length, clientHash.Length);

        if (!CoseKey.Verify(cosePublicKey, signedData, signature))
        {
            throw new WebAuthnException("Passkey signature verification failed.");
        }

        return signCount;
    }

    private static void ValidateRpIdHashAndFlags(byte[] authData, string rpId, bool requireUserVerification, out bool attested)
    {
        if (authData.Length < 37)
        {
            throw new WebAuthnException("Authenticator data is too short.");
        }

        var expectedRpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(rpId));
        if (!CryptographicOperations.FixedTimeEquals(authData.AsSpan(0, 32), expectedRpIdHash))
        {
            throw new WebAuthnException("Relying-party id hash does not match.");
        }

        var flags = authData[32];
        if ((flags & FlagUserPresent) == 0)
        {
            throw new WebAuthnException("The user-presence flag was not set.");
        }

        if (requireUserVerification && (flags & FlagUserVerified) == 0)
        {
            throw new WebAuthnException("The authenticator did not verify the user.");
        }

        attested = (flags & FlagAttestedCredentialData) != 0;
    }

    /// <summary>
    /// Reads exactly one CBOR data item (the COSE key) and returns its raw encoding, ignoring any
    /// trailing extensions.
    ///
    /// Catches the same set as the attestation parse above rather than only
    /// <see cref="CborContentException"/>: a key that is absent or cut short surfaces from
    /// <c>CborReader</c> as <see cref="InvalidOperationException"/>/<see cref="ArgumentException"/>,
    /// and letting either escape would turn a malformed registration — attacker-supplied input —
    /// into a 500 instead of the clean refusal every other failure here produces.
    /// </summary>
    private static byte[] ReadSingleCborItem(ReadOnlyMemory<byte> data)
    {
        try
        {
            var reader = new CborReader(data, CborConformanceMode.Lax, allowMultipleRootLevelValues: true);
            return reader.ReadEncodedValue().ToArray();
        }
        catch (Exception ex) when (ex is CborContentException or InvalidOperationException or ArgumentException)
        {
            throw new WebAuthnException("Malformed credential public key.");
        }
    }
}
