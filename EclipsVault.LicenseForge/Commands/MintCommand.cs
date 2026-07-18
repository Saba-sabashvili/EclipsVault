using System.Security.Cryptography;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.LicenseForge.Cli;
using EclipsVault.LicenseForge.Rendering;

namespace EclipsVault.LicenseForge.Commands;

/// <summary>
/// <c>mint</c> — sign a license token from claims supplied as flags. The private key is read from the
/// <see cref="SigningKeyEnvVar"/> environment variable (never a flag, so it can't land in shell
/// history). Every minted token is self-verified against its own public key before it is emitted, so
/// a wrong key or a drift in the canonical form fails here rather than in a customer's deployment.
/// Plain output is the bare token on one line for <c>TOKEN=$(… mint …)</c> capture.
/// </summary>
public sealed class MintCommand : Command
{
    /// <summary>Environment variable holding the base64 PKCS#8 private key (from <c>keygen</c>).</summary>
    public const string SigningKeyEnvVar = "ECLIPSVAULT_LICENSE_SIGNING_KEY";

    public MintCommand(bool pretty) : base(pretty) { }

    public override int Execute(string[] args)
    {
        var options = CommandLineOptions.Parse(args);

        var keyBase64 = Environment.GetEnvironmentVariable(SigningKeyEnvVar);
        if (string.IsNullOrWhiteSpace(keyBase64))
            return Fail($"Set {SigningKeyEnvVar} to the base64 PKCS#8 private key (from keygen).");

        var tierText = options.Get("tier");
        if (tierText is null || !Enum.TryParse<LicenseTier>(tierText, ignoreCase: true, out var tier))
            return Fail("--tier must be Community, Pro, or Enterprise.");

        var issuedTo = options.Get("to");
        if (string.IsNullOrWhiteSpace(issuedTo))
            return Fail("--to <customer name> is required.");

        var now = DateTimeOffset.UtcNow;
        var nodes = options.GetInt("nodes");
        var years = options.GetInt("years", 1);
        var featuresText = options.Get("features");
        var features = string.IsNullOrEmpty(featuresText)
            ? Array.Empty<string>()
            : featuresText.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var claims = new LicenseClaims(
            LicenseId: options.Get("id") ?? Guid.NewGuid().ToString("N")[..12],
            Tier: tier,
            IssuedTo: issuedTo,
            Contact: options.Get("contact"),
            IssuedAtUtc: now,
            NotAfterUtc: tier == LicenseTier.Community ? null : now.AddYears(years),
            MaxNodes: nodes,
            Features: features);

        using var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(keyBase64), out _);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException)
        {
            return Fail($"{SigningKeyEnvVar} is not a valid base64 PKCS#8 EC private key.");
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
            ("Expires",     claims.NotAfterUtc?.ToString("u") ?? "never",
                            claims.NotAfterUtc is null ? Theme.Positive : Theme.Text),
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
