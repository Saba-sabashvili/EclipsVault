using System.Net;

namespace EclipsVault.Core.Application.Abstractions;

public sealed record BlockedRangeDto(string Network, string Reason, DateTimeOffset BlockedAtUtc);

/// <summary>
/// Source-address blacklist consulted by middleware on every request. Blocking an
/// address blocks its surrounding range (/24 for IPv4, /64 for IPv6). Administrators
/// can inspect and lift blocks at runtime.
/// </summary>
public interface IIpBlacklist
{
    void Block(string sourceIp, string reason);

    bool IsBlocked(IPAddress address);

    IReadOnlyList<BlockedRangeDto> List();

    bool Unblock(string network);

    /// <summary>Removes every blocked range containing the address (break-glass recovery).</summary>
    bool UnblockAddress(IPAddress address);
}
