using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace EclipsVault.Infrastructure.Persistence.Repositories;

public sealed class EmailLogRepository : IEmailLogRepository
{
    private readonly EclipsVaultDbContext _context;

    public EmailLogRepository(EclipsVaultDbContext context) => _context = context;

    public async Task AddAsync(EmailLog entry, CancellationToken ct)
    {
        _context.EmailLogs.Add(entry);
        await _context.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<EmailLog>> ListRecentAsync(int max, CancellationToken ct)
        => await _context.EmailLogs
            .AsNoTracking()
            .OrderByDescending(e => e.CreatedAtUtc)
            .Take(max)
            .ToListAsync(ct);
}
