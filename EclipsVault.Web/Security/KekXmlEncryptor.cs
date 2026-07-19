using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

namespace EclipsVault.Web.Security;

/// <summary>
/// Encrypts the Data Protection key ring with the vault's own crypto engine.
///
/// The key ring has to live on a durable, shared volume to be any use, and a key ring in the clear
/// is the authentication cookie's signing key sitting in a directory — anyone who can read that
/// volume or its backups can mint a session for any account. Sealing it with the KEK means the
/// files are inert without ECLIPSVAULT_KEK, which is already held outside the database and outside
/// this volume.
///
/// Going through <see cref="ICryptoEngine"/> rather than the raw KEK is deliberate: the engine
/// unwraps with whichever KEK sealed a payload, so rotating the KEK does not lock the vault out of
/// its own key ring and sign everybody out. It also means a Vault-Transit deployment protects the
/// key ring with a master key that never enters this process.
/// </summary>
public sealed class KekXmlEncryptor : IXmlEncryptor
{
    private readonly ICryptoEngineFactory _crypto;

    public KekXmlEncryptor(ICryptoEngineFactory crypto) => _crypto = crypto;

    /// <summary>
    /// Binds the sealed blob to what it is, so a key-ring envelope cannot be passed off as a
    /// secret's — or the reverse — by anyone who can write both.
    /// </summary>
    internal static byte[] Binding => Encoding.UTF8.GetBytes("eclipsvault:data-protection-key-ring:v1");

    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        var plaintext = Encoding.UTF8.GetBytes(plaintextElement.ToString(SaveOptions.DisableFormatting));
        try
        {
            // IXmlEncryptor is a synchronous framework contract, so the one place the vault must bridge
            // to the async crypto engine is here. It is the cold path — Data Protection seals the key
            // ring when it is generated or rotated, not per request — so blocking briefly (only with a
            // network-backed engine; the local engine completes synchronously) is acceptable, unlike a
            // per-reveal call, which is exactly why ICryptoEngine is otherwise awaited.
            var sealedKey = _crypto.Create().SealAsync(plaintext, Binding, CancellationToken.None).GetAwaiter().GetResult();
            var element = new XElement("sealedKey",
                new XElement("ciphertext", Convert.ToBase64String(sealedKey.Ciphertext)),
                new XElement("wrappedDek", Convert.ToBase64String(sealedKey.WrappedDek)),
                new XElement("kekId", sealedKey.KekId),
                new XElement("algorithm", sealedKey.Algorithm));

            return new EncryptedXmlInfo(element, typeof(KekXmlDecryptor));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}
