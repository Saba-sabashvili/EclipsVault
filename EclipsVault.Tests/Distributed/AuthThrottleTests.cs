using EclipsVault.Infrastructure.Security;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Xunit;

namespace EclipsVault.Tests.Distributed;

/// <summary>
/// The throttle is what damps password guessing, so its edges are security properties: the budget
/// must actually bind, one caller must not spend another's, and a window must eventually reopen so
/// a throttle can't become a permanent lockout. The window key is pinned separately because it is
/// what lets replicas agree on a bucket without coordinating — the whole point of moving the budget
/// out of process.
/// </summary>
public class AuthThrottleTests
{
    private sealed class FakeClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static readonly DateTimeOffset Start = new(2026, 7, 16, 12, 0, 0, TimeSpan.Zero);

    private static (InMemoryAuthThrottle Throttle, FakeClock Clock) Build(int permits = 3, int windowSeconds = 60)
    {
        var clock = new FakeClock(Start);
        var throttle = new InMemoryAuthThrottle(
            new MemoryCache(new MemoryCacheOptions()),
            Options.Create(new AuthThrottleOptions { PermitLimit = permits, WindowSeconds = windowSeconds }),
            clock);

        return (throttle, clock);
    }

    [Fact]
    public async Task Permits_up_to_the_limit_then_refuses()
    {
        var (throttle, _) = Build(permits: 3);

        Assert.True(await throttle.TryAcquireAsync("10.0.0.1", CancellationToken.None));
        Assert.True(await throttle.TryAcquireAsync("10.0.0.1", CancellationToken.None));
        Assert.True(await throttle.TryAcquireAsync("10.0.0.1", CancellationToken.None));
        Assert.False(await throttle.TryAcquireAsync("10.0.0.1", CancellationToken.None));
    }

    [Fact]
    public async Task Keeps_refusing_a_caller_that_keeps_hammering_within_the_window()
    {
        // A refused attempt still spends a permit, so hammering cannot walk the counter back
        // under the limit.
        var (throttle, _) = Build(permits: 1);

        Assert.True(await throttle.TryAcquireAsync("10.0.0.1", CancellationToken.None));
        for (var i = 0; i < 5; i++)
        {
            Assert.False(await throttle.TryAcquireAsync("10.0.0.1", CancellationToken.None));
        }
    }

    [Fact]
    public async Task One_callers_budget_is_not_spent_by_another()
    {
        var (throttle, _) = Build(permits: 1);

        Assert.True(await throttle.TryAcquireAsync("10.0.0.1", CancellationToken.None));
        Assert.False(await throttle.TryAcquireAsync("10.0.0.1", CancellationToken.None));

        // A different source must start with a full budget — otherwise one noisy client would
        // lock out everyone else.
        Assert.True(await throttle.TryAcquireAsync("10.0.0.2", CancellationToken.None));
    }

    [Fact]
    public async Task The_budget_reopens_in_the_next_window()
    {
        var (throttle, clock) = Build(permits: 1, windowSeconds: 60);

        Assert.True(await throttle.TryAcquireAsync("10.0.0.1", CancellationToken.None));
        Assert.False(await throttle.TryAcquireAsync("10.0.0.1", CancellationToken.None));

        clock.Now = Start.AddSeconds(60);
        Assert.True(await throttle.TryAcquireAsync("10.0.0.1", CancellationToken.None));
    }

    [Fact]
    public async Task The_budget_still_binds_late_in_the_same_window()
    {
        var (throttle, clock) = Build(permits: 1, windowSeconds: 60);

        Assert.True(await throttle.TryAcquireAsync("10.0.0.1", CancellationToken.None));

        clock.Now = Start.AddSeconds(59);
        Assert.False(await throttle.TryAcquireAsync("10.0.0.1", CancellationToken.None));
    }

    [Fact]
    public async Task Concurrent_attempts_cannot_overspend_the_budget()
    {
        var (throttle, _) = Build(permits: 10);

        var results = await Task.WhenAll(Enumerable.Range(0, 100)
            .Select(_ => throttle.TryAcquireAsync("10.0.0.1", CancellationToken.None)));

        Assert.Equal(10, results.Count(granted => granted));
    }

    [Fact]
    public void Every_node_derives_the_same_window_key_for_the_same_instant()
    {
        // This is what lets replicas share one Redis counter with no leader or handshake.
        var a = AuthThrottleWindow.KeyFor("10.0.0.1", Start.AddSeconds(5), 60);
        var b = AuthThrottleWindow.KeyFor("10.0.0.1", Start.AddSeconds(55), 60);

        Assert.Equal(a, b);
        Assert.NotEqual(a, AuthThrottleWindow.KeyFor("10.0.0.1", Start.AddSeconds(65), 60));
        Assert.NotEqual(a, AuthThrottleWindow.KeyFor("10.0.0.2", Start.AddSeconds(5), 60));
    }

    [Fact]
    public void The_window_key_survives_a_nonsense_window_length()
        => Assert.Contains("10.0.0.1", AuthThrottleWindow.KeyFor("10.0.0.1", Start, 0));
}
