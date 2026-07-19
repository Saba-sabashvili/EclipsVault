using System.Security.Cryptography;
using EclipsVault.LicenseForge.Cli;
using EclipsVault.LicenseForge.Rendering;

namespace EclipsVault.LicenseForge.Commands;

/// <summary>
/// <c>keygen</c> — generate a fresh P-256 signing keypair. Run once: keep the private key OFFLINE and
/// paste the public key into <c>LicensePublicKey.VendorSpkiBase64</c> so the shipped app can verify
/// what this tool mints. Plain output is a stable five-line block (private key on line 2, public key
/// on line 5) so a script can capture either without parsing colour.
/// </summary>
public sealed class KeygenCommand : Command
{
    public KeygenCommand(bool pretty) : base(pretty) { }

    public override int Execute(string[] args)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = Convert.ToBase64String(ecdsa.ExportPkcs8PrivateKey());
        var publicKey = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());

        if (!Pretty)
        {
            // Stable, scriptable format — line 2 is the private key, line 5 is the public key.
            Console.WriteLine("# PRIVATE KEY (PKCS#8 base64) — keep OFFLINE, never commit:");
            Console.WriteLine(privateKey);
            Console.WriteLine();
            Console.WriteLine("# PUBLIC KEY (SPKI base64) — paste into LicensePublicKey.VendorSpkiBase64:");
            Console.WriteLine(publicKey);
            return ExitCodes.Ok;
        }

        Banner.Print();
        Render.SectionHeader("New signing keypair");
        Render.KeyBlock("PRIVATE KEY", Theme.Negative, privateKey, "PKCS#8 · keep OFFLINE, never commit");
        Render.KeyBlock("PUBLIC KEY", Theme.Accent, publicKey, "SPKI · paste into LicensePublicKey.VendorSpkiBase64");
        Console.WriteLine();
        Render.Warn("The private key is shown once — store it in your password manager now.");
        Console.WriteLine();
        return ExitCodes.Ok;
    }
}
