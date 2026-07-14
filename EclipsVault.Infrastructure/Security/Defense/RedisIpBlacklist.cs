using System.Net;
using System.Text.Json;
using EclipsVault.Infrastructure.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Redis-backed source-range blacklist shared by every node. A block is keyed by the
/// canonical range for the offending address (<see cref="NetworkRules.ToBlockRange"/> —
/// /24, /64, or the exact loopback host). Because that mapping is a pure function of the
/// address, the per-request "is this IP blocked?" check is a single O(1) key lookup on the
/// same canonical range, with no need to scan every stored block. Blocks persist until an
/// administrator (or break-glass recovery) lifts them, surviving restarts.
/// </summary>
public sealed class RedisIpBlacklist : IIpBlacklist
{
    private sealed record BlockRecord(string Reason, DateTimeOffset BlockedAtUtc);

    private readonly IConnectionMultiplexer _redis;
    private readonly string _prefix;
    private readonly ILogger<RedisIpBlacklist> _logger;

    public RedisIpBlacklist(
        IConnectionMultiplexer redis,
        IOptions<RedisOptions> options,
        ILogger<RedisIpBlacklist> logger)
    {
        _redis = redis;
        _prefix = options.Value.InstanceName;
        _logger = logger;
    }

    public async Task BlockAsync(string sourceIp, string reason, CancellationToken ct = default)
    {
        if (!IPAddress.TryParse(sourceIp, out var address))
        {
            _logger.LogWarning("Cannot blacklist unparseable source address {SourceIp}", sourceIp);
            return;
        }

        var network = NetworkRules.ToBlockRange(address).ToString();
        var record = JsonSerializer.Serialize(new BlockRecord(reason, DateTimeOffset.UtcNow));

        // First-write-wins so re-tripping the same range keeps the original timestamp/reason.
        var added = await _redis.GetDatabase().StringSetAsync(Key(network), record, when: When.NotExists);
        if (added)
        {
            _logger.LogCritical("Source range {Network} blacklisted — {Reason}", network, reason);
        }
    }

    public async Task<bool> IsBlockedAsync(IPAddress address, CancellationToken ct = default)
    {
        var network = NetworkRules.ToBlockRange(address).ToString();
        return await _redis.GetDatabase().KeyExistsAsync(Key(network));
    }

    public async Task<IReadOnlyList<BlockedRangeDto>> ListAsync(CancellationToken ct = default)
    {
        var db = _redis.GetDatabase();
        var pattern = $"{_prefix}:ipblock:*";
        var results = new List<BlockedRangeDto>();

        foreach (var key in ScanKeys(pattern))
        {
            var value = await db.StringGetAsync(key);
            if (!value.HasValue)
            {
                continue;
            }

            var network = ((string)key!)[$"{_prefix}:ipblock:".Length..];
            var record = JsonSerializer.Deserialize<BlockRecord>((string)value!);
            if (record is not null)
            {
                results.Add(new BlockedRangeDto(network, record.Reason, record.BlockedAtUtc));
            }
        }

        return results.OrderByDescending(d => d.BlockedAtUtc).ToList();
    }

    public async Task<bool> UnblockAsync(string network, CancellationToken ct = default)
    {
        var removed = await _redis.GetDatabase().KeyDeleteAsync(Key(network.Trim()));
        if (removed)
        {
            _logger.LogWarning("Blacklisted range {Network} was unblocked by an administrator", network);
        }

        return removed;
    }

    public async Task<bool> UnblockAddressAsync(IPAddress address, CancellationToken ct = default)
    {
        // An address is only ever blocked under its own canonical range, so lifting that
        // one key fully unblocks it (break-glass recovery).
        var network = NetworkRules.ToBlockRange(address).ToString();
        var removed = await _redis.GetDatabase().KeyDeleteAsync(Key(network));
        if (removed)
        {
            _logger.LogWarning("Blacklisted range {Network} lifted via break-glass recovery from {SourceIp}", network, address);
        }

        return removed;
    }

    private RedisKey Key(string network) => $"{_prefix}:ipblock:{network}";

    /// <summary>Enumerates matching keys across the connected primary endpoints (admin-only, infrequent).</summary>
    private IEnumerable<RedisKey> ScanKeys(string pattern)
    {
        foreach (var endpoint in _redis.GetEndPoints())
        {
            var server = _redis.GetServer(endpoint);
            if (!server.IsConnected || server.IsReplica)
            {
                continue;
            }

            foreach (var key in server.Keys(pattern: pattern))
            {
                yield return key;
            }
        }
    }
}
