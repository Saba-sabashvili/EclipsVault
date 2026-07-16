using System.Security.Cryptography;
using EclipsVault.Core.Domain.Exceptions;
using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// AES-256-GCM envelope encryption. Every Seal generates a fresh single-use
/// 32-byte DEK, encrypts the payload with it, then wraps the DEK with the master
/// KEK. Blob layout for both fields: nonce(12) | tag(16) | ciphertext.
/// DEK material is zeroed from memory the moment it is no longer required.
///
/// The payload is bound to the row it belongs in (see <see cref="SecretBinding"/>), so an envelope
/// lifted into a different row will not decrypt there. The binding is on the payload rather than
/// the wrapped DEK because that is sufficient: an envelope moved wholesale still fails its payload
/// tag under the new row's binding, and leaving the DEK unbound keeps KEK rotation a pure re-wrap
/// that never touches plaintext.
/// </summary>
public sealed class AesGcmCryptoEngine : ICryptoEngine
{
    public const string EngineName = "AesGcmLocal";

    private readonly IKekProvider _kekProvider;
    private readonly CryptoOptions _options;

    public AesGcmCryptoEngine(IKekProvider kekProvider, IOptions<CryptoOptions> options)
    {
        _kekProvider = kekProvider;
        _options = options.Value;
    }

    public string EngineId => EngineName;

    public SealedSecret Seal(byte[] plaintext, byte[] associatedData)
    {
        var dek = RandomNumberGenerator.GetBytes(GcmBlob.DekSize);
        try
        {
            var ciphertext = GcmBlob.Encrypt(dek, plaintext, associatedData);
            var wrappedDek = GcmBlob.Encrypt(_kekProvider.CurrentKek, dek, default);
            return new SealedSecret(ciphertext, wrappedDek, _kekProvider.CurrentKekId, SealAlgorithms.AesGcmLocal);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public byte[] Unseal(SealedSecret sealedSecret, byte[] associatedData)
    {
        var binding = LegacyBlobPolicy.BindingFor(sealedSecret.Algorithm, associatedData, _options);

        // Unwrap the DEK with whichever KEK sealed it (current or a retired one), not just the current.
        var dek = GcmBlob.Decrypt(_kekProvider.ResolveKek(sealedSecret.KekId), sealedSecret.WrappedDek, default);
        try
        {
            return GcmBlob.Decrypt(dek, sealedSecret.Ciphertext, binding);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public SealedSecret Rewrap(SealedSecret sealedSecret)
    {
        if (string.Equals(sealedSecret.KekId, _kekProvider.CurrentKekId, StringComparison.Ordinal))
        {
            return sealedSecret; // already under the current KEK
        }

        var dek = GcmBlob.Decrypt(_kekProvider.ResolveKek(sealedSecret.KekId), sealedSecret.WrappedDek, default);
        try
        {
            var rewrappedDek = GcmBlob.Encrypt(_kekProvider.CurrentKek, dek, default);
            return sealedSecret with { WrappedDek = rewrappedDek, KekId = _kekProvider.CurrentKekId };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }
}
