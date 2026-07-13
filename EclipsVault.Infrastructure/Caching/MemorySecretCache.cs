using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Caching;

public sealed class CacheOptions
{
    public const string SectionName = "Cache";

    /// <summary>Absolute TTL for cached encrypted envelopes.</summary>
    public int SecretTtlMinutes { get; set; } = 5;
}

/// <summary>
/// Cache-aside store for encrypted envelopes backed by IMemoryCache. Only ciphertext
/// and attribute metadata ever enter the cache — never decrypted values. Entries use
/// a short absolute TTL and are evicted eagerly by the service layer on every write.
/// </summary>
public sealed class MemorySecretCache : ISecretCache
{
    private readonly IMemoryCache _cache;
    private readonly TimeSpan _ttl;
    private readonly ILogger<MemorySecretCache> _logger;

    public MemorySecretCache(IMemoryCache cache, IOptions<CacheOptions> options, ILogger<MemorySecretCache> logger)
    {
        _cache = cache;
        _ttl = TimeSpan.FromMinutes(options.Value.SecretTtlMinutes);
        _logger = logger;
    }

    public bool TryGet(Guid secretId, out EncryptedSecretEnvelope? envelope)
        => _cache.TryGetValue(Key(secretId), out envelope);

    public void Set(EncryptedSecretEnvelope envelope)
        => _cache.Set(Key(envelope.Id), envelope, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = _ttl
        });

    public void Evict(Guid secretId)
    {
        _cache.Remove(Key(secretId));
        _logger.LogDebug("Evicted cached envelope for secret {SecretId}", secretId);
    }

    private static string Key(Guid secretId) => $"secret-envelope:{secretId:N}";
}
