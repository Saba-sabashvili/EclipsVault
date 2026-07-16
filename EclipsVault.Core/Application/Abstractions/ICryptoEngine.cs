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

    /// <param name="associatedData">
    /// Binds the payload to the row it is being stored in — see <see cref="SecretBinding"/>. It is
    /// authenticated but not encrypted, and the identical value must be supplied to
    /// <see cref="Unseal"/> or the read fails.
    /// </param>
    SealedSecret Seal(byte[] plaintext, byte[] associatedData);

    /// <param name="associatedData">
    /// The binding this payload was sealed with. If it does not match — because the envelope was
    /// moved into a different row — the tag check fails and nothing is returned.
    /// </param>
    byte[] Unseal(SealedSecret sealedSecret, byte[] associatedData);

    /// <summary>
    /// Re-wraps an already-sealed secret's DEK under the <em>current</em> KEK — used by key
    /// rotation. The payload ciphertext is untouched (no re-encryption); only the wrapped DEK
    /// and its <see cref="SealedSecret.KekId"/> change. The DEK is unwrapped with whichever KEK
    /// originally sealed it, so the engine must still hold that (now retired) key.
    /// </summary>
    SealedSecret Rewrap(SealedSecret sealedSecret);
}
