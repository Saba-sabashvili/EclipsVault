using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace EclipsVault.Infrastructure.Persistence.Repositories;

public sealed class MfaRecoveryCodeRepository : IMfaRecoveryCodeRepository
{
    private readonly EclipsVaultDbContext _context;

    public MfaRecoveryCodeRepository(EclipsVaultDbContext context) => _context = context;

    public async Task<IReadOnlyList<MfaRecoveryCode>> ListUnusedAsync(Guid userId, CancellationToken ct)
        => await _context.MfaRecoveryCodes
            .Where(c => c.UserId == userId && c.UsedAtUtc == null)
            .OrderBy(c => c.CreatedAtUtc)
            .ToListAsync(ct);

    public Task<int> CountUnusedAsync(Guid userId, CancellationToken ct)
        => _context.MfaRecoveryCodes.CountAsync(c => c.UserId == userId && c.UsedAtUtc == null, ct);

    public async Task ReplaceAllAsync(Guid userId, IReadOnlyList<MfaRecoveryCode> codes, CancellationToken ct)
    {
        var existing = await _context.MfaRecoveryCodes.Where(c => c.UserId == userId).ToListAsync(ct);
        _context.MfaRecoveryCodes.RemoveRange(existing);
        await _context.MfaRecoveryCodes.AddRangeAsync(codes, ct);
        await _context.SaveChangesAsync(ct);
    }

    public async Task MarkUsedAsync(MfaRecoveryCode code, CancellationToken ct)
    {
        _context.MfaRecoveryCodes.Update(code);
        await _context.SaveChangesAsync(ct);
    }

    public async Task DeleteAllAsync(Guid userId, CancellationToken ct)
    {
        var existing = await _context.MfaRecoveryCodes.Where(c => c.UserId == userId).ToListAsync(ct);
        if (existing.Count == 0)
        {
            return;
        }

        _context.MfaRecoveryCodes.RemoveRange(existing);
        await _context.SaveChangesAsync(ct);
    }
}
