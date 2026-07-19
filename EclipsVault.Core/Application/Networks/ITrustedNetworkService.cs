using System.Net;

namespace EclipsVault.Core.Application.Networks;

public sealed record TrustedNetworkDto(Guid Id, string Cidr, string Label, string AddedBy, DateTimeOffset CreatedAtUtc);

/// <summary>
/// Runtime-managed trusted networks for the ABAC network rule. Lookups are cached
/// briefly and the cache is evicted on every mutation, so a newly trusted address
/// takes effect immediately. All mutations are audited.
/// </summary>
public interface ITrustedNetworkService
{
    Task<bool> IsTrustedAsync(IPAddress address, CancellationToken ct);

    Task<IReadOnlyList<TrustedNetworkDto>> ListAsync(CancellationToken ct);

    /// <summary>Accepts a bare IP or CIDR; normalizes and persists it. Throws VaultAdminException on invalid input.</summary>
    Task<TrustedNetworkDto> AddAsync(string cidrOrIp, string label, CancellationToken ct);

    Task<bool> RemoveAsync(Guid id, CancellationToken ct);

    /// <summary>Writes the audit entry for lifting an intrusion-defence IP block.</summary>
    Task RecordUnblockedAsync(string network, CancellationToken ct);
}
