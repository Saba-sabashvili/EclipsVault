namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Signs audit checkpoints with an asymmetric key (ECDSA P-256 / SHA-256). The private key
/// never leaves the signer; only the public key is exposed, to be embedded in exported
/// bundles so anyone can verify a signature without trusting the running vault.
/// </summary>
public interface IAuditCheckpointSigner
{
    /// <summary>Produces an ECDSA signature over the canonical checkpoint bytes.</summary>
    byte[] Sign(byte[] canonical);

    /// <summary>The public key as SubjectPublicKeyInfo (SPKI) DER, for embedding in a bundle.</summary>
    byte[] PublicKeySpki { get; }

    /// <summary>Short, stable identifier (thumbprint) of the signing key.</summary>
    string KeyId { get; }
}
