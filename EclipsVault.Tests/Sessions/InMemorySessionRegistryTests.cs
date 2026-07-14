using EclipsVault.Core.Application.Sessions;
using EclipsVault.Infrastructure.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace EclipsVault.Tests.Sessions;

/// <summary>
/// The session-registry contract that both the in-process and Redis stores must honour: sessions
/// are per-user, an individual revoke removes one and cannot be undone by the cookie coming back,
/// expired sessions drop off, and the last-seen touch is throttled without losing created-at.
/// </summary>
public class InMemorySessionRegistryTests
{
    private static InMemorySessionRegistry NewRegistry()
        => new(NullLogger<InMemorySessionRegistry>.Instance);

    private static SessionObservation Obs(
        Guid user, Guid sid, string device = "Chrome on macOS", string ip = "203.0.113.5",
        DateTimeOffset? seen = null, DateTimeOffset? expires = null)
        => new(user, sid, device, ip, seen ?? DateTimeOffset.UtcNow, expires ?? DateTimeOffset.UtcNow.AddHours(1));

    [Fact]
    public async Task A_recorded_session_is_listed_for_its_owner()
    {
        var reg = NewRegistry();
        var user = Guid.NewGuid();
        var sid = Guid.NewGuid();
        await reg.RecordSeenAsync(Obs(user, sid, device: "Firefox on Linux", ip: "198.51.100.9"));

        var item = Assert.Single(await reg.ListAsync(user));
        Assert.Equal(sid, item.SessionId);
        Assert.Equal("Firefox on Linux", item.Device);
        Assert.Equal("198.51.100.9", item.IpAddress);
    }

    [Fact]
    public async Task Sessions_are_scoped_per_user()
    {
        var reg = NewRegistry();
        var owner = Guid.NewGuid();
        await reg.RecordSeenAsync(Obs(owner, Guid.NewGuid()));

        Assert.Empty(await reg.ListAsync(Guid.NewGuid())); // a different user sees nothing
    }

    [Fact]
    public async Task Revoking_a_session_removes_it_and_marks_it_revoked()
    {
        var reg = NewRegistry();
        var user = Guid.NewGuid();
        var sid = Guid.NewGuid();
        await reg.RecordSeenAsync(Obs(user, sid));

        await reg.RevokeAsync(user, sid);

        Assert.Empty(await reg.ListAsync(user));
        Assert.True(await reg.IsRevokedAsync(user, sid));
    }

    [Fact]
    public async Task A_revoked_session_cannot_resurrect_itself()
    {
        var reg = NewRegistry();
        var user = Guid.NewGuid();
        var sid = Guid.NewGuid();
        await reg.RecordSeenAsync(Obs(user, sid));
        await reg.RevokeAsync(user, sid);

        // The cookie comes back on a later request — it must not re-create the session.
        await reg.RecordSeenAsync(Obs(user, sid));

        Assert.Empty(await reg.ListAsync(user));
        Assert.True(await reg.IsRevokedAsync(user, sid));
    }

    [Fact]
    public async Task An_expired_session_is_not_listed()
    {
        var reg = NewRegistry();
        var user = Guid.NewGuid();
        await reg.RecordSeenAsync(Obs(user, Guid.NewGuid(), expires: DateTimeOffset.UtcNow.AddMinutes(-1)));

        Assert.Empty(await reg.ListAsync(user));
    }

    [Fact]
    public async Task Sessions_list_most_recently_active_first()
    {
        var reg = NewRegistry();
        var user = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var older = Guid.NewGuid();
        var newer = Guid.NewGuid();

        await reg.RecordSeenAsync(Obs(user, older, seen: now.AddMinutes(-10), expires: now.AddHours(1)));
        await reg.RecordSeenAsync(Obs(user, newer, seen: now.AddMinutes(-1), expires: now.AddHours(1)));

        var list = await reg.ListAsync(user);
        Assert.Equal(newer, list[0].SessionId);
        Assert.Equal(older, list[1].SessionId);
    }

    [Fact]
    public async Task Last_seen_is_throttled_but_created_at_is_preserved()
    {
        var reg = NewRegistry();
        var user = Guid.NewGuid();
        var sid = Guid.NewGuid();
        var t0 = DateTimeOffset.UtcNow;

        await reg.RecordSeenAsync(Obs(user, sid, seen: t0, expires: t0.AddHours(1)));
        // Within the 60s throttle window: last-seen must not move.
        await reg.RecordSeenAsync(Obs(user, sid, seen: t0.AddSeconds(30), expires: t0.AddHours(1)));

        var afterThrottled = Assert.Single(await reg.ListAsync(user));
        Assert.Equal(t0, afterThrottled.LastSeenAtUtc);

        // Past the window: last-seen advances, created-at stays put.
        await reg.RecordSeenAsync(Obs(user, sid, seen: t0.AddSeconds(90), expires: t0.AddHours(1)));

        var afterMoved = Assert.Single(await reg.ListAsync(user));
        Assert.Equal(t0.AddSeconds(90), afterMoved.LastSeenAtUtc);
        Assert.Equal(t0, afterMoved.CreatedAtUtc);
    }

    [Fact]
    public async Task An_unknown_session_is_not_revoked()
        => Assert.False(await NewRegistry().IsRevokedAsync(Guid.NewGuid(), Guid.NewGuid()));
}
