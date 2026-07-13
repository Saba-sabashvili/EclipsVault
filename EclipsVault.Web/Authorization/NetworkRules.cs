using System.Net;

namespace EclipsVault.Web.Authorization;

/// <summary>CIDR matching against the statically configured trusted ranges.</summary>
public static class NetworkRules
{
    public static IPAddress Normalize(IPAddress address)
        => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

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
}
