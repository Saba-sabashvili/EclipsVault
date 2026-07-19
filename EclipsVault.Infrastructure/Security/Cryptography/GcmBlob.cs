using System.Security.Cryptography;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// The AES-256-GCM blob format shared by both engines: <c>nonce(12) | tag(16) | ciphertext</c>.
///
/// Both <see cref="AesGcmCryptoEngine"/> and <see cref="VaultTransitCryptoEngine"/> seal payloads
/// locally with a single-use DEK and differ only in who wraps that DEK, so the payload format lives
/// here once. It used to be copied into both, which meant every change to how a payload is sealed —
/// this one included — had to be made twice and agree.
/// </summary>
internal static class GcmBlob
{
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int DekSize = 32;

    /// <param name="associatedData">Authenticated but not encrypted. Empty means no binding.</param>
    public static byte[] Encrypt(byte[] key, byte[] plaintext, ReadOnlySpan<byte> associatedData)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var tag = new byte[TagSize];
        var ciphertext = new byte[plaintext.Length];

        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        var blob = new byte[NonceSize + TagSize + ciphertext.Length];
        nonce.CopyTo(blob, 0);
        tag.CopyTo(blob, NonceSize);
        ciphertext.CopyTo(blob, NonceSize + TagSize);
        return blob;
    }

    /// <summary>
    /// Throws <see cref="AuthenticationTagMismatchException"/> if the blob was edited, or if
    /// <paramref name="associatedData"/> is not exactly what it was sealed with — which is what
    /// catches an envelope that has been moved into a row it does not belong to.
    /// </summary>
    public static byte[] Decrypt(byte[] key, byte[] blob, ReadOnlySpan<byte> associatedData)
    {
        var nonce = blob.AsSpan(0, NonceSize);
        var tag = blob.AsSpan(NonceSize, TagSize);
        var ciphertext = blob.AsSpan(NonceSize + TagSize);
        var plaintext = new byte[ciphertext.Length];

        using var gcm = new AesGcm(key, TagSize);
        gcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }
}
