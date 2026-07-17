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
///
/// The contract is asynchronous because a KMS/HSM-backed engine wraps and unwraps the DEK over the
/// network — the local engine completes synchronously, but the interface must not force a
/// network-backed one into blocking a thread-pool thread on every seal and unseal.
/// </summary>
public interface ICryptoEngine
{
    string EngineId { get; }

    /// <param name="associatedData">
    /// Binds the payload to the row it is being stored in — see <see cref="SecretBinding"/>. It is
    /// authenticated but not encrypted, and the identical value must be supplied to
    /// <see cref="UnsealAsync"/> or the read fails.
    /// </param>
    Task<SealedSecret> SealAsync(byte[] plaintext, byte[] associatedData, CancellationToken ct);

    /// <param name="associatedData">
    /// The binding this payload was sealed with. If it does not match — because the envelope was
    /// moved into a different row — the tag check fails and nothing is returned.
    /// </param>
    Task<byte[]> UnsealAsync(SealedSecret sealedSecret, byte[] associatedData, CancellationToken ct);

    /// <summary>
    /// Re-wraps an already-sealed secret's DEK under the <em>current</em> KEK — used by key
    /// rotation. The payload ciphertext is untouched (no re-encryption); only the wrapped DEK
    /// and its <see cref="SealedSecret.KekId"/> change. The DEK is unwrapped with whichever KEK
    /// originally sealed it, so the engine must still hold that (now retired) key.
    /// </summary>
    Task<SealedSecret> RewrapAsync(SealedSecret sealedSecret, CancellationToken ct);
}
