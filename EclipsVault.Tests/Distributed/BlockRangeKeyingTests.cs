using System.Net;
using EclipsVault.Core.Application.Networks;
using Xunit;

namespace EclipsVault.Tests.Distributed;

/// <summary>
/// The invariant that lets the Redis blacklist answer "is this IP blocked?" with a single
/// O(1) key lookup instead of scanning every stored block: every address inside a range
/// maps, via ToBlockRange, to the identical canonical network key. So a block keyed by any
/// one address in the range is found by a lookup keyed by any other address in it.
/// </summary>
public class BlockRangeKeyingTests
{
    [Theory]
    [InlineData("203.0.113.1")]
    [InlineData("203.0.113.40")]
    [InlineData("203.0.113.254")]
    public void All_addresses_in_a_slash24_share_one_canonical_key(string address)
        => Assert.Equal("203.0.113.0/24", NetworkRules.ToBlockRange(IPAddress.Parse(address)).ToString());

    [Theory]
    [InlineData("2001:db8:abcd:1234::1")]
    [InlineData("2001:db8:abcd:1234:ffff:ffff:ffff:ffff")]
    public void All_addresses_in_a_slash64_share_one_canonical_key(string address)
        => Assert.Equal("2001:db8:abcd:1234::/64", NetworkRules.ToBlockRange(IPAddress.Parse(address)).ToString());

    [Fact]
    public void An_ipv4_mapped_ipv6_source_keys_to_the_same_range_as_its_ipv4_form()
    {
        // A caller arriving as ::ffff:203.0.113.40 must resolve to the same block key as
        // 203.0.113.40, or a block raised against one form would miss the other.
        var mapped = NetworkRules.ToBlockRange(IPAddress.Parse("203.0.113.40").MapToIPv6()).ToString();
        var direct = NetworkRules.ToBlockRange(IPAddress.Parse("203.0.113.40")).ToString();
        Assert.Equal(direct, mapped);
    }

    [Fact]
    public void Loopback_keys_to_its_exact_host_not_a_range()
        => Assert.Equal("127.0.0.1/32", NetworkRules.ToBlockRange(IPAddress.Loopback).ToString());
}
