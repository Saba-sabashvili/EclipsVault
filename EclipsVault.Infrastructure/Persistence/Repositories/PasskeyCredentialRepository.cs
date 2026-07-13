using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace EclipsVault.Infrastructure.Persistence.Repositories;

public sealed class PasskeyCredentialRepository : IPasskeyCredentialRepository
{
    private readonly EclipsVaultDbContext _context;

    public PasskeyCredentialRepository(EclipsVaultDbContext context) => _context = context;

    public async Task AddAsync(PasskeyCredential credential, CancellationToken ct)
    {
        _context.PasskeyCredentials.Add(credential);
        await _context.SaveChangesAsync(ct);
    }

    public Task<PasskeyCredential?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken ct)
        => _context.PasskeyCredentials.FirstOrDefaultAsync(p => p.CredentialId == credentialId, ct);

    public async Task<IReadOnlyList<PasskeyCredential>> ListForUserAsync(Guid userId, CancellationToken ct)
        => await _context.PasskeyCredentials
            .AsNoTracking()
            .Where(p => p.UserId == userId)
            .OrderByDescending(p => p.CreatedAtUtc)
            .ToListAsync(ct);

    public Task<PasskeyCredential?> FindByIdForUserAsync(Guid id, Guid userId, CancellationToken ct)
        => _context.PasskeyCredentials.FirstOrDefaultAsync(p => p.Id == id && p.UserId == userId, ct);

    public async Task UpdateAsync(PasskeyCredential credential, CancellationToken ct)
    {
        _context.PasskeyCredentials.Update(credential);
        await _context.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(PasskeyCredential credential, CancellationToken ct)
    {
        _context.PasskeyCredentials.Remove(credential);
        await _context.SaveChangesAsync(ct);
    }
}
