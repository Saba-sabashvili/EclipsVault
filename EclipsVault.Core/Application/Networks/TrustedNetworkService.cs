using System.Net;
using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Exceptions;

namespace EclipsVault.Core.Application.Networks;

/// <summary>
/// Runtime-managed trusted networks for the ABAC network rule. Parsing and normalisation are
/// delegated to <see cref="NetworkRules"/>; persistence and its cache live behind
/// <see cref="ITrustedNetworkRepository"/>; the audit row for every add and remove is injected
/// into the same transaction as the change by the SaveChanges interceptor, so a trust change can
/// never be persisted unaudited.
/// </summary>
public sealed class TrustedNetworkService : ITrustedNetworkService
{
    /// <summary>
    /// Widest range an operator may trust. A /8 is ~16.7M addresses; anything broader is far
    /// more likely to be a typo than an intent, and trusting it would gut the ABAC network rule.
    /// </summary>
    private const int MinimumPrefixLength = 8;

    private readonly ITrustedNetworkRepository _repository;
    private readonly IAuditContext _actor;
    private readonly TimeProvider _clock;

    public TrustedNetworkService(ITrustedNetworkRepository repository, IAuditContext actor, TimeProvider clock)
    {
        _repository = repository;
        _actor = actor;
        _clock = clock;
    }

    public async Task<bool> IsTrustedAsync(IPAddress address, CancellationToken ct)
        => NetworkRules.IsInAnyCidr(address, await _repository.ListCidrsAsync(ct));

    public async Task<IReadOnlyList<TrustedNetworkDto>> ListAsync(CancellationToken ct)
        => (await _repository.ListAsync(ct))
            .Select(t => new TrustedNetworkDto(t.Id, t.Cidr, t.Label, t.AddedBy, t.CreatedAtUtc))
            .ToList();

    public async Task<TrustedNetworkDto> AddAsync(string cidrOrIp, string label, CancellationToken ct)
    {
        var cidr = NormalizeToCidr(cidrOrIp);

        if (await _repository.ExistsAsync(cidr, ct))
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

        await _repository.AddAsync(entity, ct);
        return new TrustedNetworkDto(entity.Id, entity.Cidr, entity.Label, entity.AddedBy, entity.CreatedAtUtc);
    }

    public async Task<bool> RemoveAsync(Guid id, CancellationToken ct)
    {
        var entity = await _repository.FindAsync(id, ct);
        if (entity is null)
        {
            return false;
        }

        await _repository.RemoveAsync(entity, ct);
        return true;
    }

    private static string NormalizeToCidr(string input)
    {
        if (!NetworkRules.TryParseCidr(input, out var cidr))
        {
            throw new VaultAdminException(
                $"'{input}' is not a valid IP address or CIDR range (e.g. 203.0.113.7 or 10.8.0.0/24).");
        }

        // A bare address canonicalises to /32 or /128, so this only ever rejects an explicit range.
        if (IPNetwork.Parse(cidr).PrefixLength < MinimumPrefixLength)
        {
            throw new VaultAdminException(
                $"'{input}' is broader than /{MinimumPrefixLength} — refusing to trust a range that large.");
        }

        return cidr;
    }
}
