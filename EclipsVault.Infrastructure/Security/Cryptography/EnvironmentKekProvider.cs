using System.Security.Cryptography;
using EclipsVault.Core.Domain.Exceptions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Security;

public sealed class CryptoOptions
{
    public const string SectionName = "Crypto";

    /// <summary>Selects the engine returned by CryptoEngineFactory (e.g. "AesGcmLocal").</summary>
    public string Engine { get; set; } = AesGcmCryptoEngine.EngineName;

    /// <summary>Environment variable holding the base64-encoded 32-byte <em>current</em> master KEK.</summary>
    public string KekEnvironmentVariable { get; set; } = "ECLIPSVAULT_KEK";

    /// <summary>
    /// Environment variable holding one or more base64-encoded <em>retired</em> KEKs (separated by
    /// ';' or ','), kept only so existing DEKs can still be unwrapped until rotation re-wraps them.
    /// </summary>
    public string RetiredKekEnvironmentVariable { get; set; } = "ECLIPSVAULT_KEK_RETIRED";

    /// <summary>Development-only escape hatch; must stay false outside local dev.</summary>
    public bool AllowDevelopmentKekFallback { get; set; }

    public string? DevelopmentKekBase64 { get; set; }

    /// <summary>Development-only retired keys (base64), used when the retired env var is unset.</summary>
    public string[] DevelopmentRetiredKeksBase64 { get; set; } = [];
}

/// <summary>
/// Supplies the master Key Encryption Keys. Holds one <em>current</em> KEK (used to wrap new DEKs)
/// plus any number of <em>retired</em> KEKs, all resolvable by id so a DEK wrapped under an older KEK
/// can still be unwrapped — the basis for zero-downtime KEK rotation.
/// </summary>
public interface IKekProvider
{
    /// <summary>Id of the current KEK (wraps new DEKs).</summary>
    string CurrentKekId { get; }

    /// <summary>The current KEK bytes.</summary>
    byte[] CurrentKek { get; }

    /// <summary>Resolves any known KEK (current or retired) by id to unwrap an existing DEK. Throws if unknown.</summary>
    byte[] ResolveKek(string kekId);

    /// <summary>All known KEK ids, current first.</summary>
    IReadOnlyList<string> KnownKekIds { get; }
}

/// <summary>
/// Loads the current KEK (and any retired KEKs) from environment variables at startup and fails fast
/// when the current key is absent or malformed. Each KEK gets a stable id derived from a hash of the key,
/// stored with every wrapped DEK, so rotation is a data operation with no schema change.
/// </summary>
public sealed class EnvironmentKekProvider : IKekProvider
{
    private const int KekSize = 32;

    private readonly Dictionary<string, byte[]> _keys = new(StringComparer.Ordinal);

    public EnvironmentKekProvider(IOptions<CryptoOptions> options, ILogger<EnvironmentKekProvider> logger)
    {
        var opts = options.Value;

        var currentBase64 = Environment.GetEnvironmentVariable(opts.KekEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(currentBase64) && opts.AllowDevelopmentKekFallback && !string.IsNullOrWhiteSpace(opts.DevelopmentKekBase64))
        {
            logger.LogWarning(
                "Master KEK loaded from DEVELOPMENT fallback configuration — set the {KekEnvironmentVariable} environment variable for any real deployment",
                opts.KekEnvironmentVariable);
            currentBase64 = opts.DevelopmentKekBase64;
        }

        if (string.IsNullOrWhiteSpace(currentBase64))
        {
            throw new CryptoConfigurationException(
                $"Master KEK not found. Set the '{opts.KekEnvironmentVariable}' environment variable to a base64-encoded 32-byte key " +
                "(e.g. generate one with: openssl rand -base64 32).");
        }

        var (currentId, currentKey) = ParseKek(currentBase64, opts.KekEnvironmentVariable);
        CurrentKekId = currentId;
        CurrentKek = currentKey;
        _keys[currentId] = currentKey;

        foreach (var retiredBase64 in RetiredKekValues(opts))
        {
            var (id, key) = ParseKek(retiredBase64, opts.RetiredKekEnvironmentVariable);
            _keys.TryAdd(id, key); // current wins on a duplicate
        }

        KnownKekIds = _keys.Keys.OrderByDescending(k => k == CurrentKekId).ThenBy(k => k, StringComparer.Ordinal).ToList();
        logger.LogInformation("Master KEK loaded; current key id {KekId}; {Count} key(s) available for unwrapping",
            CurrentKekId, _keys.Count);
    }

    public string CurrentKekId { get; }

    public byte[] CurrentKek { get; }

    public IReadOnlyList<string> KnownKekIds { get; }

    public byte[] ResolveKek(string kekId)
        => _keys.TryGetValue(kekId, out var key)
            ? key
            : throw new CryptoConfigurationException(
                $"A secret is wrapped under KEK '{kekId}', which is not loaded. Provide it as a retired key to decrypt or rotate it.");

    private static IEnumerable<string> RetiredKekValues(CryptoOptions opts)
    {
        var env = Environment.GetEnvironmentVariable(opts.RetiredKekEnvironmentVariable);
        var source = !string.IsNullOrWhiteSpace(env)
            ? env.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : opts.DevelopmentRetiredKeksBase64;

        return source.Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim());
    }

    private static (string Id, byte[] Key) ParseKek(string base64, string source)
    {
        byte[] key;
        try
        {
            key = Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            throw new CryptoConfigurationException($"A KEK from '{source}' is not valid base64.");
        }

        if (key.Length != KekSize)
        {
            throw new CryptoConfigurationException(
                $"Each KEK must be exactly {KekSize} bytes; a key from '{source}' decodes to {key.Length} bytes.");
        }

        var id = "kek-" + Convert.ToHexString(SHA256.HashData(key).AsSpan(0, 4)).ToLowerInvariant();
        return (id, key);
    }
}
