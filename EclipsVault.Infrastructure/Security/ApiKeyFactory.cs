using System.Security.Cryptography;
using System.Text;
using EclipsVault.Core.Application.ServiceAccounts;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Generates <c>evk_&lt;base64url(32 bytes)&gt;</c> tokens and hashes them with SHA-256
/// for storage/lookup. The token has 256 bits of entropy, so a plain cryptographic
/// hash (not a slow password hash) is the right choice.
/// </summary>
public sealed class ApiKeyFactory : IApiKeyFactory
{
    private const string Prefix = "evk_";
    private const int SecretBytes = 32;

    public GeneratedApiKey Generate()
    {
        var raw = Prefix + Base64UrlEncode(RandomNumberGenerator.GetBytes(SecretBytes));
        // Display prefix: scheme tag + first 6 chars of the random part.
        var display = raw[..Math.Min(raw.Length, Prefix.Length + 6)];
        return new GeneratedApiKey(raw, Hash(raw), display);
    }

    public string Hash(string token)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();

    private static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
