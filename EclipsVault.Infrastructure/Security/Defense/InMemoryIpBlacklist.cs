using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Process-local blacklist of source ranges (/24 for IPv4, /64 for IPv6; loopback is
/// pinned to its exact address). Administrators can inspect and lift blocks from the
/// Networks console. Swap for a distributed store behind the same interface when
/// running multiple nodes.
/// </summary>
public sealed class InMemoryIpBlacklist : IIpBlacklist
{
    private sealed record Entry(IPNetwork Network, BlockedRangeDto Dto);

    private readonly ConcurrentDictionary<string, Entry> _blocked = new();
    private readonly TimeProvider _clock;
    private readonly ILogger<InMemoryIpBlacklist> _logger;

    public InMemoryIpBlacklist(TimeProvider clock, ILogger<InMemoryIpBlacklist> logger)
    {
        _clock = clock;
        _logger = logger;
    }

    public void Block(string sourceIp, string reason)
    {
        if (!IPAddress.TryParse(sourceIp, out var address))
        {
            _logger.LogWarning("Cannot blacklist unparseable source address {SourceIp}", sourceIp);
            return;
        }

        var network = NetworkRules.ToBlockRange(address);
        var key = network.ToString();
        var entry = new Entry(network, new BlockedRangeDto(key, reason, _clock.GetUtcNow()));

        if (_blocked.TryAdd(key, entry))
        {
            _logger.LogCritical("Source range {Network} blacklisted — {Reason}", key, reason);
        }
    }

    public bool IsBlocked(IPAddress address)
    {
        foreach (var entry in _blocked.Values)
        {
            if (NetworkRules.Contains(entry.Network, address))
            {
                return true;
            }
        }

        return false;
    }

    public IReadOnlyList<BlockedRangeDto> List()
        => _blocked.Values.Select(e => e.Dto).OrderByDescending(d => d.BlockedAtUtc).ToList();

    public bool Unblock(string network)
    {
        if (_blocked.TryRemove(network.Trim(), out _))
        {
            _logger.LogWarning("Blacklisted range {Network} was unblocked by an administrator", network);
            return true;
        }

        return false;
    }

    public bool UnblockAddress(IPAddress address)
    {
        var removed = false;
        foreach (var (key, entry) in _blocked)
        {
            if (NetworkRules.Contains(entry.Network, address) && _blocked.TryRemove(key, out _))
            {
                removed = true;
                _logger.LogWarning("Blacklisted range {Network} lifted via break-glass recovery from {SourceIp}", key, address);
            }
        }

        return removed;
    }
}
