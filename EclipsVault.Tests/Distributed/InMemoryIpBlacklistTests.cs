using System.Net;
using EclipsVault.Infrastructure.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace EclipsVault.Tests.Distributed;

/// <summary>
/// The blacklist contract shared by the in-process and Redis stores: blocking one address
/// contains its whole /24 (or /64), blocks are enumerable and liftable, and break-glass
/// recovery lifts exactly the range that would keep an admin out.
/// </summary>
public class InMemoryIpBlacklistTests
{
    private static InMemoryIpBlacklist NewBlacklist()
        => new(TimeProvider.System, NullLogger<InMemoryIpBlacklist>.Instance);

    [Fact]
    public async Task Blocking_an_address_contains_its_whole_slash24()
    {
        var bl = NewBlacklist();
        await bl.BlockAsync("203.0.113.40", "test");

        Assert.True(await bl.IsBlockedAsync(IPAddress.Parse("203.0.113.7")));   // same /24
        Assert.False(await bl.IsBlockedAsync(IPAddress.Parse("203.0.114.7")));  // different /24
    }

    [Fact]
    public async Task List_reports_the_blocked_range_with_its_reason()
    {
        var bl = NewBlacklist();
        await bl.BlockAsync("198.51.100.9", "honey-token tripped");

        var listed = Assert.Single(await bl.ListAsync());
        Assert.Equal("198.51.100.0/24", listed.Network);
        Assert.Equal("honey-token tripped", listed.Reason);
    }

    [Fact]
    public async Task Unblock_by_network_lifts_the_block()
    {
        var bl = NewBlacklist();
        await bl.BlockAsync("198.51.100.9", "test");

        Assert.True(await bl.UnblockAsync("198.51.100.0/24"));
        Assert.False(await bl.IsBlockedAsync(IPAddress.Parse("198.51.100.9")));
    }

    [Fact]
    public async Task UnblockAddress_lifts_the_range_covering_the_caller()
    {
        var bl = NewBlacklist();
        await bl.BlockAsync("198.51.100.9", "test");

        Assert.True(await bl.UnblockAddressAsync(IPAddress.Parse("198.51.100.200"))); // same /24
        Assert.False(await bl.IsBlockedAsync(IPAddress.Parse("198.51.100.9")));
    }

    [Fact]
    public async Task Unparseable_source_is_a_no_op()
    {
        var bl = NewBlacklist();
        await bl.BlockAsync("not-an-ip", "test");

        Assert.Empty(await bl.ListAsync());
    }

    [Fact]
    public async Task Loopback_is_pinned_to_its_exact_host()
    {
        var bl = NewBlacklist();
        await bl.BlockAsync("127.0.0.1", "test");

        Assert.True(await bl.IsBlockedAsync(IPAddress.Loopback));
        var listed = Assert.Single(await bl.ListAsync());
        Assert.Equal("127.0.0.1/32", listed.Network);
    }
}
