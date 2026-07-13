using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Persistence;

/// <summary>
/// Prepares the audit hash chain at startup: it back-fills sequence numbers and hashes onto any
/// rows written before chaining existed (so the whole history becomes verifiable), then seeds the
/// in-memory <see cref="AuditChain"/> head from the persisted tail — so after a restart the next
/// audit row continues the existing chain instead of colliding with it. Runs once, before any request.
/// </summary>
public static class AuditChainInitializer
{
    public static async Task InitializeAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<EclipsVaultDbContext>();
        var chain = scope.ServiceProvider.GetRequiredService<AuditChain>();
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<EclipsVaultDbContext>>();

        var unchained = await db.AuditLogs
            .Where(a => a.Sequence == 0)
            .OrderBy(a => a.TimestampUtc).ThenBy(a => a.Id)
            .ToListAsync();

        if (unchained.Count > 0)
        {
            var tail = await LoadTailAsync(db);
            var seq = tail?.Sequence ?? 0;
            var prev = tail?.EntryHash ?? AuditRowHasher.GenesisHash;

            foreach (var row in unchained)
            {
                seq++;
                row.Sequence = seq;
                row.PreviousHash = prev;
                row.EntryHash = AuditRowHasher.Compute(row, prev);
                prev = row.EntryHash;
            }

            await db.SaveChangesAsync();
            logger.LogInformation("Audit chain: back-filled {Count} pre-existing entries into the hash chain", unchained.Count);
        }

        var head = await LoadTailAsync(db);
        chain.Seed(head?.Sequence ?? 0, head?.EntryHash);
    }

    private static Task<Core.Domain.Entities.AuditLog?> LoadTailAsync(EclipsVaultDbContext db)
        => db.AuditLogs.Where(a => a.Sequence > 0)
            .OrderByDescending(a => a.Sequence)
            .FirstOrDefaultAsync();
}
