using System.Net;
using EclipsVault.Core.Application.Networks;
using Xunit;

namespace EclipsVault.Tests.Distributed;

/// <summary>
/// The invariant that lets the Redis blacklist answer "is this IP blocked?" with a single O(1)
/// key lookup instead of scanning every stored block: <c>ToBlockRange</c> is a deterministic
/// function of the address (and the globally-configured width), so a block is found by a lookup
/// keyed the same way. By default each host keys to its own exact address; with range blocking
/// enabled, every address in a range shares one canonical key.
/// </summary>
public class BlockRangeKeyingTests
{
    [Theory]
    [InlineData("203.0.113.1")]
    [InlineData("203.0.113.40")]
    [InlineData("203.0.113.254")]
    public void By_default_each_host_keys_to_its_own_exact_address(string address)
        => Assert.Equal($"{address}/32", NetworkRules.ToBlockRange(IPAddress.Parse(address)).ToString());

    [Fact]
    public void By_default_two_hosts_in_the_same_subnet_key_differently()
    {
        var a = NetworkRules.ToBlockRange(IPAddress.Parse("203.0.113.40")).ToString();
        var b = NetworkRules.ToBlockRange(IPAddress.Parse("203.0.113.41")).ToString();
        Assert.NotEqual(a, b); // blocking one does not blackhole the other
    }

    [Theory]
    [InlineData("203.0.113.1")]
    [InlineData("203.0.113.40")]
    [InlineData("203.0.113.254")]
    public void All_addresses_in_a_slash24_share_one_canonical_key_when_range_blocking(string address)
        => Assert.Equal("203.0.113.0/24", NetworkRules.ToBlockRange(IPAddress.Parse(address), blockSurroundingRange: true).ToString());

    [Theory]
    [InlineData("2001:db8:abcd:1234::1")]
    [InlineData("2001:db8:abcd:1234:ffff:ffff:ffff:ffff")]
    public void All_addresses_in_a_slash64_share_one_canonical_key_when_range_blocking(string address)
        => Assert.Equal("2001:db8:abcd:1234::/64", NetworkRules.ToBlockRange(IPAddress.Parse(address), blockSurroundingRange: true).ToString());

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void An_ipv4_mapped_ipv6_source_keys_to_the_same_range_as_its_ipv4_form(bool range)
    {
        // A caller arriving as ::ffff:203.0.113.40 must resolve to the same block key as
        // 203.0.113.40, or a block raised against one form would miss the other.
        var mapped = NetworkRules.ToBlockRange(IPAddress.Parse("203.0.113.40").MapToIPv6(), range).ToString();
        var direct = NetworkRules.ToBlockRange(IPAddress.Parse("203.0.113.40"), range).ToString();
        Assert.Equal(direct, mapped);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Loopback_keys_to_its_exact_host_not_a_range(bool range)
        => Assert.Equal("127.0.0.1/32", NetworkRules.ToBlockRange(IPAddress.Loopback, range).ToString());
}
