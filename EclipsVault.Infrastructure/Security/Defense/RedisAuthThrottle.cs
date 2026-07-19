using EclipsVault.Infrastructure.Distributed;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Fixed-window throttle whose counter lives in Redis, so every replica spends one shared budget:
/// scaling the vault out no longer multiplies what an attacker is allowed to try.
///
/// INCR is atomic, so concurrent attempts on different nodes cannot both read the same count and
/// each decide they are within budget — the counter is the arbiter, not any node's view of it.
///
/// A Redis outage makes this throw, which refuses the request. That is deliberate: the alternative
/// is to wave authentication traffic through unmetered exactly when the vault has lost the thing
/// that meters it.
/// </summary>
public sealed class RedisAuthThrottle : IAuthThrottle
{
    private readonly IConnectionMultiplexer _redis;
    private readonly AuthThrottleOptions _options;
    private readonly string _prefix;
    private readonly TimeProvider _clock;

    public RedisAuthThrottle(
        IConnectionMultiplexer redis,
        IOptions<AuthThrottleOptions> options,
        IOptions<RedisOptions> redisOptions,
        TimeProvider clock)
    {
        _redis = redis;
        _options = options.Value;
        _prefix = redisOptions.Value.InstanceName;
        _clock = clock;
    }

    public async Task<bool> TryAcquireAsync(string partitionKey, CancellationToken ct)
    {
        var key = _prefix + AuthThrottleWindow.KeyFor(partitionKey, _clock.GetUtcNow(), _options.WindowSeconds);
        var db = _redis.GetDatabase();

        var used = await db.StringIncrementAsync(key);
        if (used == 1)
        {
            // Only the attempt that created the counter sets its lifetime, so a steady stream of
            // requests can't keep pushing the expiry out and make the window slide forever.
            await db.KeyExpireAsync(key, TimeSpan.FromSeconds(_options.WindowSeconds * 2));
        }

        return used <= _options.PermitLimit;
    }
}
