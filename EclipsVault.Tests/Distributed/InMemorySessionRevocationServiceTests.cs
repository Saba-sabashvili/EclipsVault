using EclipsVault.Infrastructure.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace EclipsVault.Tests.Distributed;

/// <summary>
/// The revocation contract that both the in-process and Redis stores must honour: a session
/// issued at or before the revocation instant is dead; the marker only ever moves forward.
/// </summary>
public class InMemorySessionRevocationServiceTests
{
    private static InMemorySessionRevocationService NewService()
        => new(NullLogger<InMemorySessionRevocationService>.Instance);

    private static readonly DateTimeOffset T0 = new(2026, 7, 14, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Unrevoked_user_is_never_revoked()
        => Assert.False(await NewService().IsRevokedAsync(Guid.NewGuid(), T0));

    [Fact]
    public async Task Session_issued_before_revocation_is_revoked()
    {
        var svc = NewService();
        var user = Guid.NewGuid();
        await svc.RevokeAsync(user, T0);

        Assert.True(await svc.IsRevokedAsync(user, T0.AddSeconds(-1)));
    }

    [Fact]
    public async Task Session_issued_exactly_at_revocation_is_revoked()
    {
        var svc = NewService();
        var user = Guid.NewGuid();
        await svc.RevokeAsync(user, T0);

        Assert.True(await svc.IsRevokedAsync(user, T0));
    }

    [Fact]
    public async Task Session_issued_after_revocation_survives()
    {
        var svc = NewService();
        var user = Guid.NewGuid();
        await svc.RevokeAsync(user, T0);

        Assert.False(await svc.IsRevokedAsync(user, T0.AddSeconds(1)));
    }

    [Fact]
    public async Task Revocation_marker_only_moves_forward()
    {
        var svc = NewService();
        var user = Guid.NewGuid();

        await svc.RevokeAsync(user, T0.AddMinutes(10));
        await svc.RevokeAsync(user, T0); // an older instant must not lower the bar

        // A session issued between the two instants stays revoked by the later marker.
        Assert.True(await svc.IsRevokedAsync(user, T0.AddMinutes(5)));
    }

    [Fact]
    public async Task Revocation_is_scoped_per_user()
    {
        var svc = NewService();
        var revoked = Guid.NewGuid();
        var other = Guid.NewGuid();
        await svc.RevokeAsync(revoked, T0);

        Assert.False(await svc.IsRevokedAsync(other, T0.AddSeconds(-1)));
    }
}
