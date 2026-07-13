using System.Text.Json;
using EclipsVault.Core.Application.Auditing;

// Standalone offline verifier for an exported EclipsVault audit bundle. It re-walks the hash
// chain and checks the signed checkpoint against the public key embedded in the bundle — with
// no access to the vault, its database, or its private key. This separation is the point: the
// trail's integrity can be proven by a third party who trusts only the published public key.
//
// Exit codes: 0 = valid, 1 = invalid (tampering/bad signature), 2 = usage or read error.

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    Console.WriteLine("EclipsVault audit-bundle verifier");
    Console.WriteLine("Usage: eclipsvault-audit-verify <bundle.json>");
    Console.WriteLine();
    Console.WriteLine("Verifies an exported audit bundle offline: re-walks the hash chain and checks the");
    Console.WriteLine("signed checkpoint against the public key inside the bundle. No access to the vault");
    Console.WriteLine("or its database is required.");
    return args.Length == 0 ? 2 : 0;
}

var path = args[0];
if (!File.Exists(path))
{
    Console.Error.WriteLine($"error: file not found: {path}");
    return 2;
}

AuditBundle? bundle;
try
{
    await using var stream = File.OpenRead(path);
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

var result = AuditBundleVerifier.Verify(bundle);

Console.WriteLine($"Bundle     : {path}");
Console.WriteLine($"Schema     : {bundle.SchemaVersion}");
Console.WriteLine($"Exported   : {bundle.ExportedAtUtc:u}");
Console.WriteLine($"Rows       : {bundle.Rows.Count}");
Console.WriteLine($"Checkpoint : sequence {bundle.Checkpoint.Sequence}, key {bundle.Checkpoint.SigningKeyId}");
Console.WriteLine();
Console.WriteLine(result.IsValid ? "RESULT: VALID" : "RESULT: INVALID");
Console.WriteLine($"  {result.Message}");
if (!result.IsValid && result.FirstBrokenSequence is { } brokenAt)
{
    Console.WriteLine($"  first broken sequence: {brokenAt}");
}

return result.IsValid ? 0 : 1;
