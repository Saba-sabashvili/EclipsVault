using System.Globalization;
using EclipsVault.Infrastructure.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Redis-backed session kill switch. Stores one key per revoked user holding the latest
/// revocation instant (Unix seconds); cookie validation on every node reads it, so a
/// revocation raised anywhere takes effect everywhere. The key carries a retention TTL
/// longer than any session lifetime, after which it self-expires.
/// </summary>
public sealed class RedisSessionRevocationService : ISessionRevocationService
{
    // Atomic "keep the newest instant": only overwrite when the incoming value is later,
    // so a race between two revocations can never move the marker backwards.
    private const string SetMaxScript = @"
local current = redis.call('GET', KEYS[1])
if (not current) or (tonumber(ARGV[1]) > tonumber(current)) then
    redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
end
return 1";

    private readonly IConnectionMultiplexer _redis;
    private readonly string _prefix;
    private readonly int _retentionSeconds;
    private readonly ILogger<RedisSessionRevocationService> _logger;

    public RedisSessionRevocationService(
        IConnectionMultiplexer redis,
        IOptions<RedisOptions> options,
        ILogger<RedisSessionRevocationService> logger)
    {
        _redis = redis;
        _prefix = options.Value.InstanceName;
        _retentionSeconds = Math.Max(1, options.Value.RevocationRetentionHours) * 3600;
        _logger = logger;
    }

    public async Task RevokeAsync(Guid userId, DateTimeOffset revokedAtUtc, CancellationToken ct = default)
    {
        var db = _redis.GetDatabase();
        await db.ScriptEvaluateAsync(
            SetMaxScript,
            new RedisKey[] { Key(userId) },
            new RedisValue[] { revokedAtUtc.ToUnixTimeSeconds(), _retentionSeconds });
        _logger.LogWarning("All sessions for user {UserId} issued at or before {RevokedAtUtc} are now revoked", userId, revokedAtUtc);
    }

    public async Task<bool> IsRevokedAsync(Guid userId, DateTimeOffset sessionIssuedAtUtc, CancellationToken ct = default)
    {
        var db = _redis.GetDatabase();
        var value = await db.StringGetAsync(Key(userId));
        return value.HasValue
            && long.TryParse((string)value!, NumberStyles.Integer, CultureInfo.InvariantCulture, out var revokedUnix)
            && sessionIssuedAtUtc.ToUnixTimeSeconds() <= revokedUnix;
    }

    private RedisKey Key(Guid userId) => $"{_prefix}:revocation:{userId:N}";
}
