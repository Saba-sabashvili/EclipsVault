using System.Security.Cryptography;

namespace EclipsVault.Core.Application.Licensing;

/// <summary>
/// Mints a signed license token from claims and a private key. Pure and shared by the vendor CLI
/// and the tests. It holds no key itself — the security boundary is possession of the private key,
/// not this code (exactly as with the audit signer, whose canonical form is also public).
/// </summary>
public static class LicenseSigner
{
    public static string Sign(LicenseClaims claims, ECDsa privateKey)
    {
        var payload = LicenseCanonical.Serialize(claims);
        var signature = privateKey.SignData(payload, HashAlgorithmName.SHA256);
        return LicenseToken.Encode(payload, signature);
    }
}
