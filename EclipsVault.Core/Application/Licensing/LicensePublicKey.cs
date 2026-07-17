namespace EclipsVault.Core.Application.Licensing;

/// <summary>
/// The vendor's license-signing PUBLIC key, pinned into the build. The app can only ever <em>verify</em>
/// with this; minting requires the matching private key, which the vendor keeps offline.
///
/// PLACEHOLDER: run <c>EclipsVault.LicenseForge keygen</c> once, keep the printed private key offline,
/// and paste the printed SubjectPublicKeyInfo (SPKI) base64 here. While this is empty, every token
/// verifies as InvalidSignature and the vault runs unlicensed (soft) — it never blocks.
/// </summary>
public static class LicensePublicKey
{
    public const string VendorSpkiBase64 = "";

    public static byte[] Spki =>
        string.IsNullOrEmpty(VendorSpkiBase64) ? [] : Convert.FromBase64String(VendorSpkiBase64);
}
