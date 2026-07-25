using System.Security.Cryptography;

namespace EclipsVault.Core.Application.Auditing;

/// <summary>
/// The short, stable identifier for an audit signing key, derived from the key itself.
///
/// <para>
/// Shared by the signer (which stamps it onto a checkpoint) and the verifier (which <em>recomputes</em>
/// it), so the two cannot drift. The recomputation is the point: a checkpoint's stored
/// <c>SigningKeyId</c> is not covered by the signature, so an edited bundle could name any key it
/// liked. Deriving the id from the public key that actually verified the signature means the value an
/// auditor reads is authenticated by construction, and editing the stored field changes nothing.
/// </para>
/// </summary>
public static class AuditSigningKeyId
{
    /// <param name="publicKeySpki">SubjectPublicKeyInfo bytes of the signing key.</param>
    public static string For(byte[] publicKeySpki)
        => "sig-" + Convert.ToHexString(SHA256.HashData(publicKeySpki).AsSpan(0, 4)).ToLowerInvariant();
}
