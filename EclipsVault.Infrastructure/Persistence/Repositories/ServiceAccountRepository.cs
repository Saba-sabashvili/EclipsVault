using EclipsVault.Core.Application.ServiceAccounts;
using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace EclipsVault.Infrastructure.Persistence.Repositories;

public sealed class ServiceAccountRepository : IServiceAccountRepository
{
    private readonly EclipsVaultDbContext _context;

    public ServiceAccountRepository(EclipsVaultDbContext context) => _context = context;

    public async Task<IReadOnlyList<ServiceAccount>> ListAsync(CancellationToken ct)
        => await _context.ServiceAccounts.AsNoTracking().OrderBy(a => a.Name).ToListAsync(ct);

    public Task<ServiceAccount?> FindAsync(Guid id, CancellationToken ct)
        => _context.ServiceAccounts.FirstOrDefaultAsync(a => a.Id == id, ct);

    public Task<bool> ExistsByNameAsync(string name, CancellationToken ct)
        => _context.ServiceAccounts.AnyAsync(a => a.Name == name, ct);

    public async Task AddAsync(ServiceAccount account, CancellationToken ct)
    {
        _context.ServiceAccounts.Add(account);
        await _context.SaveChangesAsync(ct);
    }

    public async Task UpdateAsync(ServiceAccount account, CancellationToken ct)
    {
        _context.ServiceAccounts.Update(account);
        await _context.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(ServiceAccount account, CancellationToken ct)
    {
        _context.ServiceAccounts.Remove(account); // keys cascade-delete
        await _context.SaveChangesAsync(ct);
    }

    public async Task AddKeyAsync(ApiKey key, CancellationToken ct)
    {
        _context.ApiKeys.Add(key);
        await _context.SaveChangesAsync(ct);
    }

    public Task<ApiKey?> FindKeyAsync(Guid keyId, CancellationToken ct)
        => _context.ApiKeys.FirstOrDefaultAsync(k => k.Id == keyId, ct);

    public Task<ApiKey?> FindKeyByHashAsync(string keyHash, CancellationToken ct)
        => _context.ApiKeys.Include(k => k.ServiceAccount).FirstOrDefaultAsync(k => k.KeyHash == keyHash, ct);

    public async Task UpdateKeyAsync(ApiKey key, CancellationToken ct)
    {
        _context.ApiKeys.Update(key);
        await _context.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ApiKey>> ListKeysAsync(Guid serviceAccountId, CancellationToken ct)
        => await _context.ApiKeys.AsNoTracking()
            .Where(k => k.ServiceAccountId == serviceAccountId)
            .OrderByDescending(k => k.CreatedAtUtc)
            .ToListAsync(ct);

    public Task<int> CountActiveKeysAsync(Guid serviceAccountId, DateTimeOffset asOfUtc, CancellationToken ct)
        => _context.ApiKeys.CountAsync(
            k => k.ServiceAccountId == serviceAccountId
                 && k.RevokedAtUtc == null
                 && (k.ExpiresAtUtc == null || k.ExpiresAtUtc > asOfUtc), ct);

}
