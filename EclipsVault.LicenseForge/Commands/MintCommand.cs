using System.Security.Cryptography;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.LicenseForge.Cli;
using EclipsVault.LicenseForge.Rendering;

namespace EclipsVault.LicenseForge.Commands;

/// <summary>
/// <c>mint</c> — sign a license token from claims supplied as flags. The private key is read from the
/// file named by <c>--key-file</c>, and from nowhere else: never a flag value, so it cannot land in
/// shell history or the process list, and never the environment, which every child process inherits.
/// Every minted token is self-verified against its own public key before it is emitted, so
/// a wrong key or a drift in the canonical form fails here rather than in a customer's deployment.
/// Plain output is the bare token on one line for <c>TOKEN=$(… mint …)</c> capture.
/// </summary>
public sealed class MintCommand : Command
{
    /// <summary>
    /// Every flag <c>mint</c> accepts. The parser refuses anything outside this set, because an
    /// unrecognised flag is a typo, and a typo used to mean "that claim was never supplied" — which
    /// for expiry and node count is the most generous value there is.
    /// </summary>
    private static readonly string[] MintFlags =
        ["key-file", "tier", "to", "contact", "id", "nodes", "years", "features", "expires", "trial-days"];

    public MintCommand(bool pretty) : base(pretty) { }

    public override int Execute(string[] args)
    {
        var parsed = CommandLineOptions.Parse(args, MintFlags);
        if (!parsed.Ok) return Fail(parsed.Error!);
        var options = parsed.Options!;

        var key = SigningKeySource.Resolve(options.Get("key-file"));
        if (!key.Ok)
            return Fail(key.Error!);

        var keyBase64 = key.KeyBase64!;

        var featuresText = options.Get("features");
        var features = string.IsNullOrEmpty(featuresText)
            ? Array.Empty<string>()
            : featuresText.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var now = DateTimeOffset.UtcNow;

        // --trial-days <n> mints a Max evaluation licence with an n-day hard expiry. Its presence (not
        // its value) marks a trial, so absence stays null and a normal licence is untouched.
        var trialDays = options.GetInt("trial-days");
        if (!trialDays.Ok) return Fail(trialDays.Error!);

        var nodes = options.GetInt("nodes");
        if (!nodes.Ok) return Fail(nodes.Error!);

        var years = options.GetInt("years");
        if (!years.Ok) return Fail(years.Error!);

        var expires = options.GetInt("expires");
        if (!expires.Ok) return Fail(expires.Error!);

        var build = MintClaims.Build(
            tierText: options.Get("tier"),
            issuedTo: options.Get("to"),
            contact: options.Get("contact"),
            licenseId: options.Get("id"),
            nodes: nodes.Value ?? 0,
            updateYears: years.Value ?? 1,
            features: features,
            expiresYears: expires.Value ?? 0,
            trialDays: trialDays.Value,
            now: now);
        if (!build.Ok)
            return Fail(build.Error!);

        var claims = build.Claims!;

        using var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(keyBase64), out _);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException)
        {
            return Fail("The signing key is not a valid base64 PKCS#8 EC private key.");
        }

        var token = LicenseSigner.Sign(claims, ecdsa);

        // Self-check: a freshly minted token must verify against its own public key. A wrong key or a
        // drift in the canonical form fails here, not in a customer's deployment.
        var check = LicenseVerifier.Verify(token, ecdsa.ExportSubjectPublicKeyInfo(), now);
        if (check.Status != LicenseStatus.Valid)
            return Fail($"Minted token failed self-verification ({check.Status}).");

        if (!Pretty)
        {
            Console.WriteLine(token);
            return ExitCodes.Ok;
        }

        Banner.Print();
        var effective = LicenseTierFeatures.Effective(claims);
        Render.Card("License minted",
        [
            ("Licensed to", claims.IssuedTo, Theme.Text),
            ("Tier",        claims.Tier.ToString(), Theme.Accent),
            ("License id",  claims.LicenseId, Theme.Muted),
            ("Issued",      claims.IssuedAtUtc.ToString("u"), Theme.Muted),
            // Perpetual is a legitimate outcome for a paid Max licence, but it is also what a
            // mistyped expiry flag used to produce — so it is reported plainly rather than in the
            // colour the rest of this tool uses for "went well".
            ("Expires",     claims.NotAfterUtc?.ToString("u") ?? "never (perpetual)", Theme.Text),
            ("Updates until", claims.UpdatesUntilUtc?.ToString("u") ?? "—", Theme.Muted),
            ("Nodes",       claims.MaxNodes == 0 ? "unlimited" : claims.MaxNodes.ToString(), Theme.Muted),
            ("Features",    effective.Count == 0 ? "—" : string.Join(", ", effective), Theme.Muted),
        ]);
        Render.KeyBlock("LICENSE TOKEN", Theme.Accent, token, "send to the customer · set as ECLIPSVAULT_LICENSE");
        Console.WriteLine();
        Render.Success($"Signed and self-verified as {check.Status}.");
        Console.WriteLine();
        return ExitCodes.Ok;
    }
}
