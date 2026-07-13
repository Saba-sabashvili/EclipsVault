using System.Formats.Cbor;
using System.Security.Cryptography;

namespace EclipsVault.Infrastructure.Security.WebAuthn;

/// <summary>
/// Decodes a COSE_Key (RFC 8152) as produced by an authenticator and verifies a signature
/// with it. Only the two algorithms mandated for passkeys are supported: ES256 (ECDSA over
/// NIST P-256) and RS256 (RSASSA-PKCS1-v1_5 with SHA-256). The heavy lifting — the signature
/// check itself — is delegated to the BCL's vetted primitives; this class only parses.
/// </summary>
internal static class CoseKey
{
    // COSE common + key-type-specific labels (RFC 8152 §7).
    private const int LabelKty = 1;
    private const int LabelAlg = 3;
    private const int LabelEcCrv = -1;
    private const int LabelEcX = -2;
    private const int LabelEcY = -3;
    private const int LabelRsaN = -1;
    private const int LabelRsaE = -2;

    private const int KtyEc2 = 2;
    private const int KtyRsa = 3;

    private const int AlgEs256 = -7;
    private const int AlgRs256 = -257;

    private const int CrvP256 = 1;

    /// <summary>Parses the key to confirm it is a supported type/algorithm, throwing if not.</summary>
    public static void Validate(byte[] cose) => Parse(cose);

    /// <summary>Verifies <paramref name="signature"/> over <paramref name="data"/> using the encoded public key.</summary>
    public static bool Verify(byte[] cose, byte[] data, byte[] signature)
    {
        var map = Parse(cose);
        var kty = map.Int(LabelKty);
        var alg = map.Int(LabelAlg);

        if (kty == KtyEc2 && alg == AlgEs256)
        {
            if (map.Int(LabelEcCrv) != CrvP256)
            {
                throw new WebAuthnException("Unsupported elliptic curve for the passkey.");
            }

            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = map.Bytes(LabelEcX), Y = map.Bytes(LabelEcY) }
            });

            // WebAuthn ES256 signatures are ASN.1/DER encoded (SEQUENCE of two INTEGERs).
            return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }

        if (kty == KtyRsa && alg == AlgRs256)
        {
            using var rsa = RSA.Create(new RSAParameters
            {
                Modulus = map.Bytes(LabelRsaN),
                Exponent = map.Bytes(LabelRsaE)
            });

            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        throw new WebAuthnException("Unsupported passkey public-key algorithm.");
    }

    private static CoseMap Parse(byte[] cose)
    {
        try
        {
            var reader = new CborReader(cose, CborConformanceMode.Lax);
            var count = reader.ReadStartMap() ?? throw new WebAuthnException("COSE key is not a definite-length map.");

            var map = new CoseMap();
            for (var i = 0; i < count; i++)
            {
                var label = reader.ReadInt32();
                object value = reader.PeekState() switch
                {
                    CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger => reader.ReadInt64(),
                    CborReaderState.ByteString => reader.ReadByteString(),
                    CborReaderState.TextString => reader.ReadTextString(),
                    _ => throw new WebAuthnException("Unsupported value type in COSE key.")
                };
                map.Add(label, value);
            }

            reader.ReadEndMap();

            if (!map.Has(LabelKty) || !map.Has(LabelAlg))
            {
                throw new WebAuthnException("COSE key is missing its key type or algorithm.");
            }

            return map;
        }
        catch (CborContentException)
        {
            throw new WebAuthnException("Malformed COSE public key.");
        }
        catch (InvalidOperationException)
        {
            throw new WebAuthnException("Malformed COSE public key.");
        }
    }

    private sealed class CoseMap
    {
        private readonly Dictionary<int, object> _entries = [];

        public void Add(int label, object value) => _entries[label] = value;

        public bool Has(int label) => _entries.ContainsKey(label);

        public int Int(int label)
            => _entries.TryGetValue(label, out var v) && v is long l
                ? checked((int)l)
                : throw new WebAuthnException($"COSE key label {label} is missing or not an integer.");

        public byte[] Bytes(int label)
            => _entries.TryGetValue(label, out var v) && v is byte[] b
                ? b
                : throw new WebAuthnException($"COSE key label {label} is missing or not a byte string.");
    }
}
