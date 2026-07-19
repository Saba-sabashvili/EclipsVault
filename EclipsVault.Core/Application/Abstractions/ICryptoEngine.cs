namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Output of an envelope-encryption operation: the payload sealed with a single-use
/// DEK, and that DEK sealed with the master KEK.
/// </summary>
public sealed record SealedSecret(byte[] Ciphertext, byte[] WrappedDek, string KekId, string Algorithm);

/// <summary>
/// Envelope-encryption engine. The default implementation is local AES-256-GCM;
/// swapping to a cloud KMS is a configuration change (see ICryptoEngineFactory),
/// the business layer never changes.
/// </summary>
public interface ICryptoEngine
{
    string EngineId { get; }

    SealedSecret Seal(byte[] plaintext);

    byte[] Unseal(SealedSecret sealedSecret);

    /// <summary>
    /// Re-wraps an already-sealed secret's DEK under the <em>current</em> KEK — used by key
    /// rotation. The payload ciphertext is untouched (no re-encryption); only the wrapped DEK
    /// and its <see cref="SealedSecret.KekId"/> change. The DEK is unwrapped with whichever KEK
    /// originally sealed it, so the engine must still hold that (now retired) key.
    /// </summary>
    SealedSecret Rewrap(SealedSecret sealedSecret);
}
