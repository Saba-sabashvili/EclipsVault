using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Fixed-window throttle held in this process. Correct for a single node; on several it grants each
/// replica the full budget, so <see cref="RedisAuthThrottle"/> is the one to use when scaled out.
/// </summary>
public sealed class InMemoryAuthThrottle : IAuthThrottle
{
    private sealed class Counter
    {
        public int Value;
    }

    private readonly IMemoryCache _cache;
    private readonly AuthThrottleOptions _options;
    private readonly TimeProvider _clock;

    public InMemoryAuthThrottle(IMemoryCache cache, IOptions<AuthThrottleOptions> options, TimeProvider clock)
    {
        _cache = cache;
        _options = options.Value;
        _clock = clock;
    }

    public Task<bool> TryAcquireAsync(string partitionKey, CancellationToken ct)
    {
        var key = AuthThrottleWindow.KeyFor(partitionKey, _clock.GetUtcNow(), _options.WindowSeconds);

        var counter = _cache.GetOrCreate(key, entry =>
        {
            // Outlive the window itself so a counter can't be evicted mid-window and reset the budget.
            entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(_options.WindowSeconds * 2);
            return new Counter();
        })!;

        var used = Interlocked.Increment(ref counter.Value);
        return Task.FromResult(used <= _options.PermitLimit);
    }
}
