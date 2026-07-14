using System.Net;
using System.Net.Sockets;

namespace EclipsVault.Core.Application.Networks;

/// <summary>
/// Canonical IP / CIDR helpers, shared by ABAC trusted-network evaluation, the runtime
/// trusted-network store, the intrusion blacklist, and per-key IP allow-listing. Keeping
/// address normalisation and range semantics in one place stops the layers from drifting
/// apart (e.g. one treating an IPv4-mapped IPv6 address differently from another).
/// </summary>
public static class NetworkRules
{
    /// <summary>Collapses an IPv4-mapped IPv6 address to its IPv4 form so comparisons are consistent.</summary>
    public static IPAddress Normalize(IPAddress address)
        => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    /// <summary>True if the (normalised) address falls in any of the CIDR ranges. Unparseable ranges are skipped.</summary>
    public static bool IsInAnyCidr(IPAddress? address, IEnumerable<string> cidrs)
    {
        if (address is null)
        {
            return false;
        }

        var normalized = Normalize(address);
        foreach (var cidr in cidrs)
        {
            if (IPNetwork.TryParse(cidr, out var network) && network.Contains(normalized))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Membership test that normalises the address first.</summary>
    public static bool Contains(IPNetwork network, IPAddress address) => network.Contains(Normalize(address));

    /// <summary>
    /// The range to blacklist for an offending address: the exact host for loopback, otherwise
    /// the /24 (IPv4) or /64 (IPv6) it sits in, so an attacker rotating within a subnet stays contained.
    /// </summary>
    public static IPNetwork ToBlockRange(IPAddress address)
    {
        var normalized = Normalize(address);
        if (IPAddress.IsLoopback(normalized))
        {
            var host = normalized.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            return new IPNetwork(normalized, host);
        }

        var bytes = normalized.GetAddressBytes();
        if (normalized.AddressFamily == AddressFamily.InterNetwork)
        {
            bytes[3] = 0;
            return new IPNetwork(new IPAddress(bytes), 24);
        }

        for (var i = 8; i < bytes.Length; i++)
        {
            bytes[i] = 0;
        }

        return new IPNetwork(new IPAddress(bytes), 64);
    }

    /// <summary>
    /// Parses an IP address or CIDR range into canonical CIDR text (a bare IP becomes /32 or
    /// /128). Returns false for anything unparseable. Used to validate operator-entered ranges.
    /// </summary>
    public static bool TryParseCidr(string input, out string canonical)
    {
        input = input.Trim();
        if (IPAddress.TryParse(input, out var ip))
        {
            var normalized = Normalize(ip);
            canonical = normalized.AddressFamily == AddressFamily.InterNetwork ? $"{normalized}/32" : $"{normalized}/128";
            return true;
        }

        if (IPNetwork.TryParse(input, out var network))
        {
            canonical = network.ToString();
            return true;
        }

        canonical = string.Empty;
        return false;
    }
}
