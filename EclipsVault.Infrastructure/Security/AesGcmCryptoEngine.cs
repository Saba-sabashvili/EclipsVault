using System.Security.Cryptography;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// AES-256-GCM envelope encryption. Every Seal generates a fresh single-use
/// 32-byte DEK, encrypts the payload with it, then wraps the DEK with the master
/// KEK. Blob layout for both fields: nonce(12) | tag(16) | ciphertext.
/// DEK material is zeroed from memory the moment it is no longer required.
/// </summary>
public sealed class AesGcmCryptoEngine : ICryptoEngine
{
    public const string EngineName = "AesGcmLocal";

    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int DekSize = 32;

    private readonly IKekProvider _kekProvider;

    public AesGcmCryptoEngine(IKekProvider kekProvider) => _kekProvider = kekProvider;

    public string EngineId => EngineName;

    public SealedSecret Seal(byte[] plaintext)
    {
        var dek = RandomNumberGenerator.GetBytes(DekSize);
        try
        {
            var ciphertext = EncryptBlob(dek, plaintext);
            var wrappedDek = EncryptBlob(_kekProvider.CurrentKek, dek);
            return new SealedSecret(ciphertext, wrappedDek, _kekProvider.CurrentKekId, "AES-256-GCM");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public byte[] Unseal(SealedSecret sealedSecret)
    {
        // Unwrap the DEK with whichever KEK sealed it (current or a retired one), not just the current.
        var dek = DecryptBlob(_kekProvider.ResolveKek(sealedSecret.KekId), sealedSecret.WrappedDek);
        try
        {
            return DecryptBlob(dek, sealedSecret.Ciphertext);
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

        var dek = DecryptBlob(_kekProvider.ResolveKek(sealedSecret.KekId), sealedSecret.WrappedDek);
        try
        {
            var rewrappedDek = EncryptBlob(_kekProvider.CurrentKek, dek);
            return sealedSecret with { WrappedDek = rewrappedDek, KekId = _kekProvider.CurrentKekId };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    private static byte[] EncryptBlob(byte[] key, byte[] plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var tag = new byte[TagSize];
        var ciphertext = new byte[plaintext.Length];

        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag);

        var blob = new byte[NonceSize + TagSize + ciphertext.Length];
        nonce.CopyTo(blob, 0);
        tag.CopyTo(blob, NonceSize);
        ciphertext.CopyTo(blob, NonceSize + TagSize);
        return blob;
    }

    private static byte[] DecryptBlob(byte[] key, byte[] blob)
    {
        var nonce = blob.AsSpan(0, NonceSize);
        var tag = blob.AsSpan(NonceSize, TagSize);
        var ciphertext = blob.AsSpan(NonceSize + TagSize);
        var plaintext = new byte[ciphertext.Length];

        using var gcm = new AesGcm(key, TagSize);
        gcm.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}
