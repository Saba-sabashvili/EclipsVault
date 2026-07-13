using EclipsVault.Core.Domain.Entities;

namespace EclipsVault.Core.Application.ServiceAccounts;

public interface IServiceAccountRepository
{
    Task<IReadOnlyList<ServiceAccount>> ListAsync(CancellationToken ct);

    Task<ServiceAccount?> FindAsync(Guid id, CancellationToken ct);

    Task<bool> ExistsByNameAsync(string name, CancellationToken ct);

    Task AddAsync(ServiceAccount account, CancellationToken ct);

    Task UpdateAsync(ServiceAccount account, CancellationToken ct);

    Task DeleteAsync(ServiceAccount account, CancellationToken ct);

    Task AddKeyAsync(ApiKey key, CancellationToken ct);

    Task<ApiKey?> FindKeyAsync(Guid keyId, CancellationToken ct);

    /// <summary>Looks up a key by its stored hash, including its parent account, for authentication.</summary>
    Task<ApiKey?> FindKeyByHashAsync(string keyHash, CancellationToken ct);

    Task UpdateKeyAsync(ApiKey key, CancellationToken ct);

    Task<IReadOnlyList<ApiKey>> ListKeysAsync(Guid serviceAccountId, CancellationToken ct);

    Task<int> CountActiveKeysAsync(Guid serviceAccountId, DateTimeOffset asOfUtc, CancellationToken ct);
}
