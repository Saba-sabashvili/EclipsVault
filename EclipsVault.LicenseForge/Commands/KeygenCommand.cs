using System.Security.Cryptography;
using EclipsVault.LicenseForge.Cli;
using EclipsVault.LicenseForge.Rendering;

namespace EclipsVault.LicenseForge.Commands;

/// <summary>
/// <c>keygen</c> — generate a fresh P-256 signing keypair. Run once: keep the private key OFFLINE and
/// paste the public key into <c>LicensePublicKey.VendorSpkiBase64</c> so the shipped app can verify
/// what this tool mints. Plain output is a stable five-line block (private key on line 2, public key
/// on line 5) so a script can capture either without parsing colour.
///
/// <para>
/// <c>--out &lt;path&gt;</c> writes the private key straight to a file (owner-only) and prints only the
/// public half. Prefer it. Displaying a private key means it must be selected, copied and pasted to be
/// useful, and every one of those steps can drop it somewhere it cannot be recalled from — a terminal
/// scrollback, a clipboard manager, a chat window. Writing it to disk skips all of them.
/// </para>
/// </summary>
public sealed class KeygenCommand : Command
{
    public KeygenCommand(bool pretty) : base(pretty) { }

    public override int Execute(string[] args)
    {
        var options = CommandLineOptions.Parse(args);
        var outPath = options.Get("out");

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = Convert.ToBase64String(ecdsa.ExportPkcs8PrivateKey());
        var publicKey = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());

        if (outPath is not null)
        {
            return WriteKeyFile(outPath, privateKey, publicKey);
        }

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
        Render.Info("Next time, prefer: keygen --out <path> — it never displays the private key.");
        Console.WriteLine();
        return ExitCodes.Ok;
    }

    /// <summary>
    /// Writes the private key to <paramref name="path"/>, owner-read-only, and prints only the public
    /// key. Refuses to overwrite: silently replacing a signing key would orphan every licence ever
    /// issued under it, and that is not a mistake anyone should be able to make in one keystroke.
    /// </summary>
    private int WriteKeyFile(string path, string privateKey, string publicKey)
    {
        if (File.Exists(path))
        {
            return Fail($"'{path}' already exists. Refusing to overwrite a signing key — every licence signed with the existing one would stop verifying. Move it aside first if you really mean to replace it.");
        }

        try
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // Create with owner-only permissions before writing, so the key is never briefly readable.
            if (!OperatingSystem.IsWindows())
            {
                using (File.Create(path)) { }
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            File.WriteAllText(path, privateKey + Environment.NewLine);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Fail($"Could not write '{path}': {ex.Message}");
        }

        if (!Pretty)
        {
            Console.WriteLine($"# PRIVATE KEY written to {path} (owner-only). Back it up somewhere offline.");
            Console.WriteLine("# PUBLIC KEY (SPKI base64) — paste into LicensePublicKey.VendorSpkiBase64:");
            Console.WriteLine(publicKey);
            return ExitCodes.Ok;
        }

        Banner.Print();
        Render.SectionHeader("New signing keypair");
        Render.KeyBlock("PUBLIC KEY", Theme.Accent, publicKey, "SPKI · paste into LicensePublicKey.VendorSpkiBase64");
        Console.WriteLine();
        Render.Success($"Private key written to {path} (owner-only). It was never displayed.");
        Render.Warn("Back it up offline now. Lose it and no deployed version can be licensed again.");
        Console.WriteLine();
        return ExitCodes.Ok;
    }
}
