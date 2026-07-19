using System.Text.Json;
using EclipsVault.Infrastructure.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace EclipsVault.Infrastructure.Caching;

/// <summary>
/// Redis-backed cache-aside store for encrypted envelopes, shared by every node so a write
/// on one node evicts the stale envelope for all of them. Only ciphertext and attribute
/// metadata are stored (the envelope's byte fields serialise as base64) — never decrypted
/// values. Entries carry the same short absolute TTL as the in-process cache.
/// </summary>
public sealed class RedisSecretCache : ISecretCache
{
    private readonly IConnectionMultiplexer _redis;
    private readonly string _prefix;
    private readonly TimeSpan _ttl;
    private readonly ILogger<RedisSecretCache> _logger;

    public RedisSecretCache(
        IConnectionMultiplexer redis,
        IOptions<RedisOptions> redisOptions,
        IOptions<CacheOptions> cacheOptions,
        ILogger<RedisSecretCache> logger)
    {
        _redis = redis;
        _prefix = redisOptions.Value.InstanceName;
        _ttl = TimeSpan.FromMinutes(cacheOptions.Value.SecretTtlMinutes);
        _logger = logger;
    }

    public async Task<EncryptedSecretEnvelope?> GetAsync(Guid secretId, CancellationToken ct = default)
    {
        var value = await _redis.GetDatabase().StringGetAsync(Key(secretId));
        return value.HasValue ? JsonSerializer.Deserialize<EncryptedSecretEnvelope>((string)value!) : null;
    }

    public async Task SetAsync(EncryptedSecretEnvelope envelope, CancellationToken ct = default)
    {
        var payload = JsonSerializer.Serialize(envelope);
        await _redis.GetDatabase().StringSetAsync(Key(envelope.Id), payload, _ttl);
    }

    public async Task EvictAsync(Guid secretId, CancellationToken ct = default)
    {
        await _redis.GetDatabase().KeyDeleteAsync(Key(secretId));
        _logger.LogDebug("Evicted cached envelope for secret {SecretId}", secretId);
    }

    private RedisKey Key(Guid secretId) => $"{_prefix}:secret-envelope:{secretId:N}";
}
