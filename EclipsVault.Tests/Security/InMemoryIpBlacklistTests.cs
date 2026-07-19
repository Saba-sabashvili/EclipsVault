using System.Net;
using EclipsVault.Infrastructure.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace EclipsVault.Tests.Security;

/// <summary>
/// The intrusion blacklist's containment scope. By default a block covers only the exact offending
/// host — so one honey-token trip cannot deny the vault to a whole shared-egress subnet; with range
/// blocking enabled it covers the surrounding /24 (or /64). Blocks are enumerable and liftable, and
/// break-glass recovery lifts exactly what would keep an admin out.
/// </summary>
public class InMemoryIpBlacklistTests
{
    private static InMemoryIpBlacklist NewBlacklist(bool blockSurroundingRange = false)
        => new(
            TimeProvider.System,
            Options.Create(new IntrusionResponseOptions { BlockSurroundingRange = blockSurroundingRange }),
            NullLogger<InMemoryIpBlacklist>.Instance);

    [Fact]
    public void By_default_blocking_an_address_contains_only_that_host()
    {
        var bl = NewBlacklist();
        bl.Block("203.0.113.40", "test");

        Assert.True(bl.IsBlocked(IPAddress.Parse("203.0.113.40")));   // the offender
        Assert.False(bl.IsBlocked(IPAddress.Parse("203.0.113.7")));   // a neighbour on the same /24 is spared
    }

    [Fact]
    public void Range_blocking_contains_the_whole_slash24()
    {
        var bl = NewBlacklist(blockSurroundingRange: true);
        bl.Block("203.0.113.40", "test");

        Assert.True(bl.IsBlocked(IPAddress.Parse("203.0.113.7")));    // same /24
        Assert.False(bl.IsBlocked(IPAddress.Parse("203.0.114.7")));   // different /24
    }

    [Fact]
    public void List_reports_the_exact_host_by_default()
    {
        var bl = NewBlacklist();
        bl.Block("198.51.100.9", "honey-token tripped");

        var listed = Assert.Single(bl.List());
        Assert.Equal("198.51.100.9/32", listed.Network);
        Assert.Equal("honey-token tripped", listed.Reason);
    }

    [Fact]
    public void List_reports_the_range_when_range_blocking()
    {
        var bl = NewBlacklist(blockSurroundingRange: true);
        bl.Block("198.51.100.9", "honey-token tripped");

        var listed = Assert.Single(bl.List());
        Assert.Equal("198.51.100.0/24", listed.Network);
    }

    [Fact]
    public void Unblock_by_network_lifts_the_block()
    {
        var bl = NewBlacklist();
        bl.Block("198.51.100.9", "test");

        Assert.True(bl.Unblock("198.51.100.9/32"));
        Assert.False(bl.IsBlocked(IPAddress.Parse("198.51.100.9")));
    }

    [Fact]
    public void UnblockAddress_lifts_the_block_covering_the_caller()
    {
        var bl = NewBlacklist();
        bl.Block("198.51.100.9", "test");

        Assert.True(bl.UnblockAddress(IPAddress.Parse("198.51.100.9")));
        Assert.False(bl.IsBlocked(IPAddress.Parse("198.51.100.9")));
    }

    [Fact]
    public void UnblockAddress_in_range_mode_lifts_the_whole_range_covering_the_caller()
    {
        var bl = NewBlacklist(blockSurroundingRange: true);
        bl.Block("198.51.100.9", "test");

        Assert.True(bl.UnblockAddress(IPAddress.Parse("198.51.100.200"))); // same /24, break-glass
        Assert.False(bl.IsBlocked(IPAddress.Parse("198.51.100.9")));
    }

    [Fact]
    public void Unparseable_source_is_a_no_op()
    {
        var bl = NewBlacklist();
        bl.Block("not-an-ip", "test");

        Assert.Empty(bl.List());
    }

    [Fact]
    public void Loopback_is_pinned_to_its_exact_host()
    {
        var bl = NewBlacklist();
        bl.Block("127.0.0.1", "test");

        Assert.True(bl.IsBlocked(IPAddress.Loopback));
        var listed = Assert.Single(bl.List());
        Assert.Equal("127.0.0.1/32", listed.Network);
    }
}
