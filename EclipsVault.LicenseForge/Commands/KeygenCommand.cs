using System.Security.Cryptography;
using EclipsVault.LicenseForge.Cli;
using EclipsVault.LicenseForge.Rendering;

namespace EclipsVault.LicenseForge.Commands;

/// <summary>
/// <c>keygen</c> — generate a fresh P-256 signing keypair. Run once: keep the private key OFFLINE and
/// paste the public key into <c>LicensePublicKey.VendorSpkiBase64</c> so the shipped app can verify
/// what this tool mints. Only the public half is ever printed.
///
/// <para><b><c>--out &lt;path&gt;</c> is required.</b> It writes the private key straight to a file the
/// tool creates owner-only, and displays only the public key. Printing a private key means it has to be
/// selected, copied and pasted to be useful, and every one of those steps can drop it somewhere it
/// cannot be recalled from — terminal scrollback, a clipboard manager, a chat window, or a world-readable
/// file the moment the operator redirects stdout. That path used to be the default and is now gone: this
/// key cannot be revoked, so the one convenience it bought was never worth the exposure.</para>
/// </summary>
public sealed class KeygenCommand : Command
{
    /// <summary>Every flag <c>keygen</c> accepts; anything else is refused rather than ignored.</summary>
    private static readonly string[] KeygenFlags = ["out"];

    public KeygenCommand(bool pretty) : base(pretty) { }

    public override int Execute(string[] args)
    {
        var parsed = CommandLineOptions.Parse(args, KeygenFlags);
        if (!parsed.Ok) return Fail(parsed.Error!);
        var options = parsed.Options!;
        var outPath = options.Get("out");

        // Refuse before generating. There is no branch here that prints a private key, so there is no
        // way to reach one by holding the command wrong.
        if (string.IsNullOrWhiteSpace(outPath))
        {
            return Fail(
                "keygen needs --out <path>: the private key is written to that file and never displayed. " +
                "Choose a path outside the repository and outside any cloud-synced folder.");
        }

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = Convert.ToBase64String(ecdsa.ExportPkcs8PrivateKey());
        var publicKey = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());

        return WriteKeyFile(outPath, privateKey, publicKey);
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
