using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Persistence;

/// <summary>
/// Back-fills sequence numbers and hashes onto any audit rows written before chaining existed, so
/// the whole history becomes verifiable. Runs once at startup, before any request.
///
/// There is nothing to seed: <see cref="AuditChain"/> reads its head from the database on every
/// write, which is what lets replicas share one chain. A start-up snapshot would be stale the
/// moment another node appended.
/// </summary>
public static class AuditChainInitializer
{
    public static async Task InitializeAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<EclipsVaultDbContext>();
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
    }

    private static Task<Core.Domain.Entities.AuditLog?> LoadTailAsync(EclipsVaultDbContext db)
        => db.AuditLogs.Where(a => a.Sequence > 0)
            .OrderByDescending(a => a.Sequence)
            .FirstOrDefaultAsync();
}
