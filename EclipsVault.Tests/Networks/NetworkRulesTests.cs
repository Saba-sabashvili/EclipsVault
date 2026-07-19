using System.Net;
using EclipsVault.Core.Application.Networks;
using Xunit;

namespace EclipsVault.Tests.Networks;

public class NetworkRulesTests
{
    [Theory]
    [InlineData("10.0.0.5", "10.0.0.0/24", true)]
    [InlineData("10.0.1.5", "10.0.0.0/24", false)]
    [InlineData("192.168.7.3", "192.168.0.0/16", true)]
    [InlineData("172.16.0.1", "10.0.0.0/8", false)]
    public void IsInAnyCidr_matches_ipv4(string ip, string cidr, bool expected)
        => Assert.Equal(expected, NetworkRules.IsInAnyCidr(IPAddress.Parse(ip), [cidr]));

    [Fact]
    public void IsInAnyCidr_is_false_for_a_null_address()
        => Assert.False(NetworkRules.IsInAnyCidr(null, ["0.0.0.0/0"]));

    [Fact]
    public void IsInAnyCidr_skips_unparseable_ranges_but_honours_valid_ones()
        => Assert.True(NetworkRules.IsInAnyCidr(IPAddress.Parse("10.0.0.1"), ["not-a-cidr", "10.0.0.0/8"]));

    [Fact]
    public void IsInAnyCidr_matches_an_ipv4_mapped_ipv6_source_against_an_ipv4_range()
    {
        // A client arriving as ::ffff:10.0.0.5 must match a 10.0.0.0/24 rule — the exact bug
        // that a single canonical Normalize() prevents across ABAC, the blacklist, and key binding.
        var mapped = IPAddress.Parse("10.0.0.5").MapToIPv6();
        Assert.True(NetworkRules.IsInAnyCidr(mapped, ["10.0.0.0/24"]));
    }

    [Fact]
    public void Normalize_collapses_ipv4_mapped_ipv6()
        => Assert.Equal(IPAddress.Parse("203.0.113.7"), NetworkRules.Normalize(IPAddress.Parse("203.0.113.7").MapToIPv6()));

    [Fact]
    public void ToBlockRange_pins_the_offending_ipv4_to_its_exact_host_by_default()
        => Assert.Equal("10.20.30.40/32", NetworkRules.ToBlockRange(IPAddress.Parse("10.20.30.40")).ToString());

    [Fact]
    public void ToBlockRange_pins_the_offending_ipv6_to_its_exact_host_by_default()
        => Assert.Equal("2001:db8:abcd:1234::1/128", NetworkRules.ToBlockRange(IPAddress.Parse("2001:db8:abcd:1234::1")).ToString());

    [Fact]
    public void ToBlockRange_widens_the_ipv4_to_a_slash24_when_range_blocking_is_enabled()
        => Assert.Equal("10.20.30.0/24", NetworkRules.ToBlockRange(IPAddress.Parse("10.20.30.40"), blockSurroundingRange: true).ToString());

    [Fact]
    public void ToBlockRange_widens_the_ipv6_to_a_slash64_when_range_blocking_is_enabled()
        => Assert.Equal("2001:db8:abcd:1234::/64", NetworkRules.ToBlockRange(IPAddress.Parse("2001:db8:abcd:1234::1"), blockSurroundingRange: true).ToString());

    [Fact]
    public void ToBlockRange_pins_loopback_to_its_exact_host()
        => Assert.Equal("127.0.0.1/32", NetworkRules.ToBlockRange(IPAddress.Loopback).ToString());

    [Fact]
    public void ToBlockRange_pins_loopback_to_its_exact_host_even_when_range_blocking_is_enabled()
        => Assert.Equal("127.0.0.1/32", NetworkRules.ToBlockRange(IPAddress.Loopback, blockSurroundingRange: true).ToString());

    [Theory]
    [InlineData("203.0.113.7", "203.0.113.7/32")]
    [InlineData("10.0.0.0/24", "10.0.0.0/24")]
    [InlineData("2001:db8::1", "2001:db8::1/128")]
    public void TryParseCidr_canonicalises_ips_and_ranges(string input, string expected)
    {
        Assert.True(NetworkRules.TryParseCidr(input, out var canonical));
        Assert.Equal(expected, canonical);
    }

    [Fact]
    public void TryParseCidr_rejects_garbage()
        => Assert.False(NetworkRules.TryParseCidr("nonsense", out _));
}
