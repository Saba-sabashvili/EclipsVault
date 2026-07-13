namespace EclipsVault.Core.Application.ServiceAccounts;

/// <summary>A freshly generated API key: the raw token (shown once), its stored hash, and a display prefix.</summary>
public sealed record GeneratedApiKey(string RawToken, string Hash, string Prefix);

/// <summary>
/// Creates and hashes API-key tokens. Tokens are high-entropy random values, so a fast
/// cryptographic hash (SHA-256) is used for storage and lookup — Argon2 is reserved for
/// low-entropy user passwords.
/// </summary>
public interface IApiKeyFactory
{
    GeneratedApiKey Generate();

    /// <summary>Hashes a presented token the same way as at generation, for verification.</summary>
    string Hash(string token);
}
