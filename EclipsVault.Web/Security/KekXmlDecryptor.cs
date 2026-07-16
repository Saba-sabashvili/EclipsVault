using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

namespace EclipsVault.Web.Security;

/// <summary>
/// Reads back what <see cref="KekXmlEncryptor"/> sealed. Data Protection names this type inside each
/// encrypted key element and activates it with the root service provider, which is why it takes an
/// <see cref="IServiceProvider"/> rather than its dependency directly.
/// </summary>
public sealed class KekXmlDecryptor : IXmlDecryptor
{
    private readonly ICryptoEngineFactory _crypto;

    public KekXmlDecryptor(IServiceProvider services)
        => _crypto = services.GetRequiredService<ICryptoEngineFactory>();

    public XElement Decrypt(XElement encryptedElement)
    {
        var sealedKey = new SealedSecret(
            Convert.FromBase64String(Value(encryptedElement, "ciphertext")),
            Convert.FromBase64String(Value(encryptedElement, "wrappedDek")),
            Value(encryptedElement, "kekId"),
            Value(encryptedElement, "algorithm"));

        var plaintext = _crypto.Create().Unseal(sealedKey, KekXmlEncryptor.Binding);
        try
        {
            return XElement.Parse(Encoding.UTF8.GetString(plaintext));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static string Value(XElement element, string name)
        => element.Element(name)?.Value
           ?? throw new CryptographicException(
               $"The Data Protection key ring is missing '{name}'. It was not written by this vault, or has been " +
               "edited; either way the keys protecting every session cannot be trusted.");
}
