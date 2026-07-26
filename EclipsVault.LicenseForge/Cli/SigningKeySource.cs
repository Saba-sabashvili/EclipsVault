using System.Security.Cryptography;

namespace EclipsVault.LicenseForge.Cli;

/// <summary>
/// Resolves the licence-signing private key from a file or the environment, and — when it cannot —
/// says precisely what is wrong.
///
/// <para>
/// The diagnostics are the point. A signing key reaches this tool through a clipboard, and every way
/// that goes wrong produces the same useless outcome otherwise: "not a valid key". Pasting the public
/// half, pasting something else entirely, a paste that silently truncated at a line break — each is a
/// distinct mistake with a distinct fix, and each is invisible when the prompt does not echo. So they
/// are distinguished here by shape alone. Nothing in an error message ever includes key material.
/// </para>
/// </summary>
public static class SigningKeySource
{
    /// <summary>Environment variable carrying the base64 PKCS#8 private key.</summary>
    public const string EnvVar = "ECLIPSVAULT_LICENSE_SIGNING_KEY";

    /// <summary>A PKCS#8 P-256 private key is this long in base64, give or take a couple of chars.</summary>
    private const int ExpectedPrivateKeyLength = 185;

    /// <summary>Base64 prefix of a SubjectPublicKeyInfo — i.e. someone pasted the public half.</summary>
    private const string PublicKeyPrefix = "MFkw";

    /// <summary>Base64 prefix of the PKCS#8 private key this tool wants.</summary>
    private const string PrivateKeyPrefix = "MIGH";

    /// <summary>The resolved key, or the reason it could not be resolved. Never both.</summary>
    public sealed record Result(string? KeyBase64, string? Error, string Origin)
    {
        public bool Ok => KeyBase64 is not null;
    }

    /// <summary>
    /// Resolves from <paramref name="keyFilePath"/> when given, otherwise from <paramref name="envValue"/>.
    /// The file wins because it is the explicit request; falling back silently would hide a typo'd path.
    /// </summary>
    public static Result Resolve(string? keyFilePath, string? envValue)
    {
        if (!string.IsNullOrWhiteSpace(keyFilePath))
        {
            if (!File.Exists(keyFilePath))
            {
                return Fail($"No signing key file at '{keyFilePath}'. Check the path — this is not falling back to ${EnvVar}, because a mistyped path should not silently sign with a different key.");
            }

            string contents;
            try
            {
                contents = File.ReadAllText(keyFilePath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return Fail($"Could not read '{keyFilePath}': {ex.Message}");
            }

            return Validate(contents, $"file '{keyFilePath}'");
        }

        if (string.IsNullOrWhiteSpace(envValue))
        {
            return Fail(
                $"No signing key. Either pass --key-file <path>, or set ${EnvVar} to the base64 PKCS#8 private key. " +
                "A key file is the safer of the two: it keeps the key out of your shell history and out of the " +
                "process list, and you can see what you pasted.");
        }

        return Validate(envValue, $"${EnvVar}");
    }

    /// <summary>
    /// Checks the candidate is a usable EC private key, reporting the specific failure. Whitespace is
    /// tolerated: a key file that ends in a newline, or was saved by an editor that added one, is not a
    /// mistake worth failing over.
    /// </summary>
    private static Result Validate(string candidate, string origin)
    {
        var trimmed = candidate.Trim();

        if (trimmed.Length == 0)
        {
            return Fail($"The signing key from {origin} is empty.");
        }

        if (trimmed.StartsWith(PublicKeyPrefix, StringComparison.Ordinal))
        {
            return Fail(
                $"The value in {origin} is the PUBLIC key, not the private one. A public key starts '{PublicKeyPrefix}' " +
                $"and is about 124 characters; the private key starts '{PrivateKeyPrefix}' and is about " +
                $"{ExpectedPrivateKeyLength}. The public key is the half that ships in the app — signing needs the other one.");
        }

        if (trimmed.Contains('\n') || trimmed.Contains('\r'))
        {
            return Fail(
                $"The signing key from {origin} spans multiple lines. It must be one unbroken line of base64 — " +
                "a key that wrapped when it was copied will have been truncated.");
        }

        byte[] der;
        try
        {
            der = Convert.FromBase64String(trimmed);
        }
        catch (FormatException)
        {
            var hint = trimmed.Length < 100
                ? $" It is only {trimmed.Length} characters, so this looks like something other than a key — a password, or a truncated paste."
                : string.Empty;
            return Fail($"The value in {origin} is not valid base64.{hint}");
        }

        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(der, out var read);
            if (read != der.Length)
            {
                return Fail($"The signing key from {origin} has {der.Length - read} trailing byte(s) — it is not cleanly a PKCS#8 key.");
            }
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            var hint = trimmed.Length < 100
                ? $" It is only {trimmed.Length} characters; a PKCS#8 P-256 private key is about {ExpectedPrivateKeyLength}. This looks like something other than a key."
                : string.Empty;
            return Fail($"The value in {origin} is valid base64 but not a PKCS#8 EC private key.{hint}");
        }

        return new Result(trimmed, null, origin);
    }

    private static Result Fail(string error) => new(null, error, string.Empty);
}
