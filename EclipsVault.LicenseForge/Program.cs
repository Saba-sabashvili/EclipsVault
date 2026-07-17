using System.Security.Cryptography;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;

// Vendor-side license tool. `keygen` makes a keypair (keep the private key offline; paste the public
// key into LicensePublicKey.VendorSpkiBase64). `mint` signs a license token from a private key held
// in ECLIPSVAULT_LICENSE_SIGNING_KEY. Exit codes: 0 ok, 2 usage/error.
const string KeyEnv = "ECLIPSVAULT_LICENSE_SIGNING_KEY";

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    Console.WriteLine("EclipsVault license tool");
    Console.WriteLine("  keygen                             generate a P-256 keypair");
    Console.WriteLine("  mint --tier <Community|Pro|Enterprise> --to <name> [--contact <email>]");
    Console.WriteLine("       [--nodes <n>] [--years <n>] [--features a,b,c] [--id <id>]");
    Console.WriteLine();
    Console.WriteLine($"  mint reads the private key (base64 PKCS#8) from ${KeyEnv}.");
    return args.Length == 0 ? 2 : 0;
}

switch (args[0])
{
    case "keygen":
        return KeyGen();
    case "mint":
        return Mint(args);
    default:
        Console.Error.WriteLine($"error: unknown command '{args[0]}'");
        return 2;
}

static int KeyGen()
{
    using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var priv = Convert.ToBase64String(ecdsa.ExportPkcs8PrivateKey());
    var pub = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
    Console.WriteLine("# PRIVATE KEY (PKCS#8 base64) — keep OFFLINE, never commit:");
    Console.WriteLine(priv);
    Console.WriteLine();
    Console.WriteLine("# PUBLIC KEY (SPKI base64) — paste into LicensePublicKey.VendorSpkiBase64:");
    Console.WriteLine(pub);
    return 0;
}

static int Mint(string[] args)
{
    var opt = ParseOptions(args);

    var keyB64 = Environment.GetEnvironmentVariable(KeyEnv);
    if (string.IsNullOrWhiteSpace(keyB64))
    {
        Console.Error.WriteLine($"error: set {KeyEnv} to the base64 PKCS#8 private key (from keygen).");
        return 2;
    }
    if (!opt.TryGetValue("tier", out var tierText) || !Enum.TryParse<LicenseTier>(tierText, true, out var tier))
    {
        Console.Error.WriteLine("error: --tier must be Community, Pro, or Enterprise.");
        return 2;
    }
    if (!opt.TryGetValue("to", out var issuedTo) || string.IsNullOrWhiteSpace(issuedTo))
    {
        Console.Error.WriteLine("error: --to <customer name> is required.");
        return 2;
    }

    var now = DateTimeOffset.UtcNow;
    int.TryParse(opt.GetValueOrDefault("nodes"), out var nodes);
    var years = int.TryParse(opt.GetValueOrDefault("years"), out var y) ? y : 1;
    var features = opt.TryGetValue("features", out var f) && f.Length > 0
        ? f.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        : Array.Empty<string>();

    var claims = new LicenseClaims(
        LicenseId: opt.GetValueOrDefault("id") ?? Guid.NewGuid().ToString("N")[..12],
        Tier: tier,
        IssuedTo: issuedTo,
        Contact: opt.GetValueOrDefault("contact"),
        IssuedAtUtc: now,
        NotAfterUtc: tier == LicenseTier.Community ? null : now.AddYears(years),
        MaxNodes: nodes,
        Features: features);

    using var ecdsa = ECDsa.Create();
    ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(keyB64), out _);

    var token = LicenseSigner.Sign(claims, ecdsa);

    // Self-check: the freshly minted token must verify against the matching public key.
    var check = LicenseVerifier.Verify(token, ecdsa.ExportSubjectPublicKeyInfo(), now);
    if (check.Status != LicenseStatus.Valid)
    {
        Console.Error.WriteLine($"error: minted token failed self-verification ({check.Status}).");
        return 2;
    }

    Console.WriteLine(token);
    return 0;
}

static Dictionary<string, string> ParseOptions(string[] args)
{
    var opt = new Dictionary<string, string>(StringComparer.Ordinal);
    for (var i = 1; i < args.Length - 1; i++)
    {
        if (args[i].StartsWith("--", StringComparison.Ordinal))
        {
            opt[args[i][2..]] = args[i + 1];
            i++;
        }
    }
    return opt;
}
