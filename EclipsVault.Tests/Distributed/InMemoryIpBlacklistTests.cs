using System.Net;
using EclipsVault.Infrastructure.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace EclipsVault.Tests.Distributed;

/// <summary>
/// The blacklist contract shared by the in-process and Redis stores. By default a block contains
/// only the exact offending host — so one trip cannot deny the vault to a whole shared-egress
/// subnet; with range blocking enabled it contains the surrounding /24 (or /64). Blocks are
/// enumerable and liftable, and break-glass recovery lifts exactly what would keep an admin out.
/// </summary>
public class InMemoryIpBlacklistTests
{
    private static InMemoryIpBlacklist NewBlacklist(bool blockSurroundingRange = false)
        => new(
            TimeProvider.System,
            Options.Create(new IntrusionResponseOptions { BlockSurroundingRange = blockSurroundingRange }),
            NullLogger<InMemoryIpBlacklist>.Instance);

    [Fact]
    public async Task By_default_blocking_an_address_contains_only_that_host()
    {
        var bl = NewBlacklist();
        await bl.BlockAsync("203.0.113.40", "test");

        Assert.True(await bl.IsBlockedAsync(IPAddress.Parse("203.0.113.40")));   // the offender
        Assert.False(await bl.IsBlockedAsync(IPAddress.Parse("203.0.113.7")));   // a neighbour on the same /24 is spared
    }

    [Fact]
    public async Task Range_blocking_contains_the_whole_slash24()
    {
        var bl = NewBlacklist(blockSurroundingRange: true);
        await bl.BlockAsync("203.0.113.40", "test");

        Assert.True(await bl.IsBlockedAsync(IPAddress.Parse("203.0.113.7")));    // same /24
        Assert.False(await bl.IsBlockedAsync(IPAddress.Parse("203.0.114.7")));   // different /24
    }

    [Fact]
    public async Task List_reports_the_exact_host_by_default()
    {
        var bl = NewBlacklist();
        await bl.BlockAsync("198.51.100.9", "honey-token tripped");

        var listed = Assert.Single(await bl.ListAsync());
        Assert.Equal("198.51.100.9/32", listed.Network);
        Assert.Equal("honey-token tripped", listed.Reason);
    }

    [Fact]
    public async Task List_reports_the_range_when_range_blocking()
    {
        var bl = NewBlacklist(blockSurroundingRange: true);
        await bl.BlockAsync("198.51.100.9", "honey-token tripped");

        var listed = Assert.Single(await bl.ListAsync());
        Assert.Equal("198.51.100.0/24", listed.Network);
    }

    [Fact]
    public async Task Unblock_by_network_lifts_the_block()
    {
        var bl = NewBlacklist();
        await bl.BlockAsync("198.51.100.9", "test");

        Assert.True(await bl.UnblockAsync("198.51.100.9/32"));
        Assert.False(await bl.IsBlockedAsync(IPAddress.Parse("198.51.100.9")));
    }

    [Fact]
    public async Task UnblockAddress_lifts_the_block_covering_the_caller()
    {
        var bl = NewBlacklist();
        await bl.BlockAsync("198.51.100.9", "test");

        Assert.True(await bl.UnblockAddressAsync(IPAddress.Parse("198.51.100.9")));
        Assert.False(await bl.IsBlockedAsync(IPAddress.Parse("198.51.100.9")));
    }

    [Fact]
    public async Task UnblockAddress_in_range_mode_lifts_the_whole_range_covering_the_caller()
    {
        var bl = NewBlacklist(blockSurroundingRange: true);
        await bl.BlockAsync("198.51.100.9", "test");

        Assert.True(await bl.UnblockAddressAsync(IPAddress.Parse("198.51.100.200"))); // same /24, break-glass
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
