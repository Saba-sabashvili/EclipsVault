using System.Security.Cryptography;
using System.Text.Json;
using EclipsVault.Core.Application.Auditing;

// Standalone offline verifier for an exported EclipsVault audit bundle. It re-walks the hash
// chain and checks the signed checkpoint — with no access to the vault, its database, or its
// private key. This separation is the point: the trail's integrity can be proven by a third party.
//
// Pass --expected-key <public-key.pem> to PIN the signing key. Without it, a "VALID" result
// proves only that the bundle is internally consistent and signed by whatever key it carries —
// an insider who rewrote the chain and re-signed it with their own key would also pass. Pinning
// the key the auditor holds out-of-band is what proves the bundle was signed by the vault.
//
// Exit codes: 0 = valid, 1 = invalid (tampering/bad signature/wrong key), 2 = usage or read error.

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    Console.WriteLine("EclipsVault audit-bundle verifier");
    Console.WriteLine("Usage: eclipsvault-audit-verify <bundle.json> [--expected-key <public-key.pem>]");
    Console.WriteLine();
    Console.WriteLine("Verifies an exported audit bundle offline: re-walks the hash chain and checks the");
    Console.WriteLine("signed checkpoint. No access to the vault or its database is required.");
    Console.WriteLine();
    Console.WriteLine("  --expected-key <path>   Pin the signing key: require the bundle to be signed by");
    Console.WriteLine("                          this exact public key (PEM). Strongly recommended — without");
    Console.WriteLine("                          it, a rewritten-and-re-signed bundle also verifies.");
    return args.Length == 0 ? 2 : 0;
}

string? bundlePath = null;
string? expectedKeyPath = null;
for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--expected-key":
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine("error: --expected-key requires a path to a PEM public key.");
                return 2;
            }
            expectedKeyPath = args[++i];
            break;
        default:
            if (bundlePath is not null)
            {
                Console.Error.WriteLine($"error: unexpected argument '{args[i]}'.");
                return 2;
            }
            bundlePath = args[i];
            break;
    }
}

if (bundlePath is null)
{
    Console.Error.WriteLine("error: no bundle file given.");
    return 2;
}

if (!File.Exists(bundlePath))
{
    Console.Error.WriteLine($"error: file not found: {bundlePath}");
    return 2;
}

// Load and normalise the pinned key (if any) to canonical SubjectPublicKeyInfo bytes, so the
// comparison never turns on PEM/DER encoding differences.
byte[]? expectedSpki = null;
if (expectedKeyPath is not null)
{
    if (!File.Exists(expectedKeyPath))
    {
        Console.Error.WriteLine($"error: expected-key file not found: {expectedKeyPath}");
        return 2;
    }

    try
    {
        using var expected = ECDsa.Create();
        expected.ImportFromPem(await File.ReadAllTextAsync(expectedKeyPath));
        expectedSpki = expected.ExportSubjectPublicKeyInfo();
    }
    catch (Exception ex) when (ex is CryptographicException or ArgumentException)
    {
        Console.Error.WriteLine($"error: could not read a public key from {expectedKeyPath}: {ex.Message}");
        return 2;
    }
}

AuditBundle? bundle;
try
{
    await using var stream = File.OpenRead(bundlePath);
    bundle = await JsonSerializer.DeserializeAsync<AuditBundle>(stream);
}
catch (JsonException ex)
{
    Console.Error.WriteLine($"error: not a readable audit bundle: {ex.Message}");
    return 2;
}

if (bundle is null)
{
    Console.Error.WriteLine("error: the bundle was empty.");
    return 2;
}

var result = AuditBundleVerifier.Verify(bundle, expectedSpki);

Console.WriteLine($"Bundle     : {bundlePath}");
Console.WriteLine($"Schema     : {bundle.SchemaVersion}");
Console.WriteLine($"Exported   : {bundle.ExportedAtUtc:u}");
Console.WriteLine($"Rows       : {bundle.Rows.Count}");
Console.WriteLine($"Checkpoint : sequence {bundle.Checkpoint.Sequence}, key {bundle.Checkpoint.SigningKeyId}");
Console.WriteLine($"Key pinned : {(expectedSpki is null ? "no" : "yes")}");
Console.WriteLine();
Console.WriteLine(result.IsValid ? "RESULT: VALID" : "RESULT: INVALID");
Console.WriteLine($"  {result.Message}");
if (!result.IsValid && result.FirstBrokenSequence is { } brokenAt)
{
    Console.WriteLine($"  first broken sequence: {brokenAt}");
}

if (result.IsValid && expectedSpki is null)
{
    Console.WriteLine();
    Console.WriteLine("  CAUTION: no key was pinned (--expected-key). This confirms the bundle is internally");
    Console.WriteLine("  consistent and signed by its own embedded key — NOT that the key is the vault's.");
    Console.WriteLine("  Re-run with --expected-key <the vault's published public key> to prove authenticity.");
}

return result.IsValid ? 0 : 1;
