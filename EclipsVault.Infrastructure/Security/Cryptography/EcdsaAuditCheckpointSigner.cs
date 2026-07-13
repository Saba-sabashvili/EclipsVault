using System.Security.Cryptography;
using EclipsVault.Core.Domain.Exceptions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Security;

public sealed class AuditSigningOptions
{
    public const string SectionName = "AuditSigning";

    /// <summary>Environment variable holding the base64 PKCS#8 EC (P-256) private key.</summary>
    public string KeyEnvironmentVariable { get; set; } = "ECLIPSVAULT_AUDIT_SIGNING_KEY";

    /// <summary>Development-only: generate an ephemeral in-memory key when none is configured.</summary>
    public bool AllowDevelopmentEphemeralKey { get; set; }

    /// <summary>Development-only base64 PKCS#8 EC private key (persistent across restarts if set).</summary>
    public string? DevelopmentKeyBase64 { get; set; }
}

/// <summary>
/// Signs audit checkpoints with ECDSA over the NIST P-256 curve (SHA-256). The private key is
/// loaded from the environment; in Development an ephemeral key may be generated so the feature
/// works out of the box — each run then has its own key, which is fine because every exported
/// bundle carries the public key that signed it. The private key never leaves this object.
/// </summary>
public sealed class EcdsaAuditCheckpointSigner : IAuditCheckpointSigner, IDisposable
{
    private readonly ECDsa _ecdsa;

    public EcdsaAuditCheckpointSigner(IOptions<AuditSigningOptions> options, ILogger<EcdsaAuditCheckpointSigner> logger)
    {
        var opts = options.Value;
        var configured = Environment.GetEnvironmentVariable(opts.KeyEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(configured) && opts.AllowDevelopmentEphemeralKey)
        {
            configured = opts.DevelopmentKeyBase64;
        }

        if (!string.IsNullOrWhiteSpace(configured))
        {
            _ecdsa = ECDsa.Create();
            _ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(configured), out _);
        }
        else if (opts.AllowDevelopmentEphemeralKey)
        {
            _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            logger.LogWarning(
                "Audit checkpoint signing key generated EPHEMERALLY for development — set {KeyEnvironmentVariable} " +
                "to a persistent base64 PKCS#8 P-256 key so exported bundles keep a stable public identity",
                opts.KeyEnvironmentVariable);
        }
        else
        {
            throw new CryptoConfigurationException(
                $"No audit signing key. Set '{opts.KeyEnvironmentVariable}' to a base64-encoded PKCS#8 EC (P-256) private key.");
        }

        PublicKeySpki = _ecdsa.ExportSubjectPublicKeyInfo();
        // Short, stable id = first 4 bytes of SHA-256(public key), matching the KEK id convention.
        KeyId = "sig-" + Convert.ToHexString(SHA256.HashData(PublicKeySpki).AsSpan(0, 4)).ToLowerInvariant();
    }

    public byte[] PublicKeySpki { get; }

    public string KeyId { get; }

    public byte[] Sign(byte[] canonical) => _ecdsa.SignData(canonical, HashAlgorithmName.SHA256);

    public void Dispose() => _ecdsa.Dispose();
}
