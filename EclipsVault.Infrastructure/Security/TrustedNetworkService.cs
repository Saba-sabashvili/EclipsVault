using System.Net;
using System.Net.Sockets;
using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Core.Domain.Exceptions;
using EclipsVault.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// DB-backed trusted networks with a short-lived parse cache. The cache is evicted
/// on every mutation so trusting a new address takes effect on the next request.
/// Every mutation writes its audit row in the same SaveChanges batch (atomic).
/// </summary>
public sealed class TrustedNetworkService : ITrustedNetworkService
{
    private const string CacheKey = "trusted-networks:parsed";
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly EclipsVaultDbContext _db;
    private readonly IMemoryCache _cache;
    private readonly IAuditContext _actor;
    private readonly TimeProvider _clock;
    private readonly ILogger<TrustedNetworkService> _logger;

    public TrustedNetworkService(
        EclipsVaultDbContext db,
        IMemoryCache cache,
        IAuditContext actor,
        TimeProvider clock,
        ILogger<TrustedNetworkService> logger)
    {
        _db = db;
        _cache = cache;
        _actor = actor;
        _clock = clock;
        _logger = logger;
    }

    public async Task<bool> IsTrustedAsync(IPAddress address, CancellationToken ct)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var networks = await _cache.GetOrCreateAsync(CacheKey, async entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = CacheTtl;
            var cidrs = await _db.TrustedNetworks.AsNoTracking().Select(t => t.Cidr).ToListAsync(ct);
            var parsed = new List<IPNetwork>(cidrs.Count);
            foreach (var cidr in cidrs)
            {
                if (IPNetwork.TryParse(cidr, out var network))
                {
                    parsed.Add(network);
                }
            }

            return parsed;
        });

        return networks is not null && networks.Any(n => n.Contains(address));
    }

    public async Task<IReadOnlyList<TrustedNetworkDto>> ListAsync(CancellationToken ct)
        => await _db.TrustedNetworks
            .AsNoTracking()
            .OrderBy(t => t.CreatedAtUtc)
            .Select(t => new TrustedNetworkDto(t.Id, t.Cidr, t.Label, t.AddedBy, t.CreatedAtUtc))
            .ToListAsync(ct);

    public async Task<TrustedNetworkDto> AddAsync(string cidrOrIp, string label, CancellationToken ct)
    {
        var cidr = NormalizeToCidr(cidrOrIp);

        if (await _db.TrustedNetworks.AnyAsync(t => t.Cidr == cidr, ct))
        {
            throw new VaultAdminException($"The range '{cidr}' is already trusted.");
        }

        var entity = new TrustedNetwork
        {
            Id = Guid.NewGuid(),
            Cidr = cidr,
            Label = string.IsNullOrWhiteSpace(label) ? "Unlabelled" : label.Trim(),
            AddedBy = _actor.Username ?? "system",
            CreatedAtUtc = _clock.GetUtcNow()
        };

        _db.TrustedNetworks.Add(entity);
        AddAuditRow(AuditAction.TrustedNetworkAdded, cidr, entity.Label);
        await _db.SaveChangesAsync(ct);
        _cache.Remove(CacheKey);

        _logger.LogInformation("Trusted network {Cidr} ({Label}) added by {Username}", cidr, entity.Label, entity.AddedBy);
        return new TrustedNetworkDto(entity.Id, entity.Cidr, entity.Label, entity.AddedBy, entity.CreatedAtUtc);
    }

    public async Task<bool> RemoveAsync(Guid id, CancellationToken ct)
    {
        var entity = await _db.TrustedNetworks.FirstOrDefaultAsync(t => t.Id == id, ct);
        if (entity is null)
        {
            return false;
        }

        _db.TrustedNetworks.Remove(entity);
        AddAuditRow(AuditAction.TrustedNetworkRemoved, entity.Cidr, entity.Label);
        await _db.SaveChangesAsync(ct);
        _cache.Remove(CacheKey);

        _logger.LogWarning("Trusted network {Cidr} removed by {Username}", entity.Cidr, _actor.Username ?? "system");
        return true;
    }

    public async Task RecordUnblockedAsync(string network, CancellationToken ct)
    {
        AddAuditRow(AuditAction.IpRangeUnblocked, network, "Intrusion-defence block lifted");
        await _db.SaveChangesAsync(ct);
    }

    private void AddAuditRow(AuditAction action, string network, string? details)
        => _db.AuditLogs.Add(new AuditLog
        {
            Id = Guid.NewGuid(),
            TimestampUtc = _clock.GetUtcNow(),
            UserId = _actor.UserId,
            Username = _actor.Username ?? "system",
            SourceIp = _actor.SourceIp ?? "internal",
            Action = action,
            ResourceType = nameof(TrustedNetwork),
            ResourceName = network,
            Details = details
        });

    private static string NormalizeToCidr(string input)
    {
        input = input.Trim();

        if (IPAddress.TryParse(input, out var ip))
        {
            if (ip.IsIPv4MappedToIPv6)
            {
                ip = ip.MapToIPv4();
            }

            return ip.AddressFamily == AddressFamily.InterNetwork ? $"{ip}/32" : $"{ip}/128";
        }

        if (IPNetwork.TryParse(input, out var network))
        {
            if (network.PrefixLength < 8)
            {
                throw new VaultAdminException($"'{input}' is broader than /8 — refusing to trust a range that large.");
            }

            return network.ToString();
        }

        throw new VaultAdminException($"'{input}' is not a valid IP address or CIDR range (e.g. 203.0.113.7 or 10.8.0.0/24).");
    }
}
