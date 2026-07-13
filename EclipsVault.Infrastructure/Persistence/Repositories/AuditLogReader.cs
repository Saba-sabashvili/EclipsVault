using Microsoft.EntityFrameworkCore;

namespace EclipsVault.Infrastructure.Persistence.Repositories;

public sealed class AuditLogReader : IAuditLogReader
{
    private readonly EclipsVaultDbContext _db;

    public AuditLogReader(EclipsVaultDbContext db) => _db = db;

    public async Task<IReadOnlyList<AuditEntryDto>> ListRecentAsync(int count, string? username, CancellationToken ct)
    {
        var query = _db.AuditLogs.AsNoTracking();
        if (!string.IsNullOrEmpty(username))
        {
            query = query.Where(a => a.Username == username);
        }

        return await query
            .OrderByDescending(a => a.TimestampUtc)
            .Take(count)
            .Select(a => new AuditEntryDto(
                a.Id, a.TimestampUtc, a.Username, a.SourceIp, a.Action,
                a.ResourceType, a.ResourceName, a.Details, a.IsCritical))
            .ToListAsync(ct);
    }

    public Task<int> CountCriticalSinceAsync(DateTimeOffset sinceUtc, CancellationToken ct)
        => _db.AuditLogs.AsNoTracking().CountAsync(a => a.IsCritical && a.TimestampUtc >= sinceUtc, ct);

    public async Task<AuditIntegrityReport> VerifyIntegrityAsync(CancellationToken ct)
    {
        var rows = await _db.AuditLogs.AsNoTracking()
            .Where(a => a.Sequence > 0)
            .OrderBy(a => a.Sequence)
            .ToListAsync(ct);

        if (rows.Count == 0)
        {
            return new AuditIntegrityReport(true, 0, null, "No chained audit entries yet.");
        }

        var expectedPrevious = AuditRowHasher.GenesisHash;
        for (var i = 0; i < rows.Count; i++)
        {
            var row = rows[i];

            if (i > 0 && row.Sequence != rows[i - 1].Sequence + 1)
            {
                return new AuditIntegrityReport(false, rows.Count, row.Sequence,
                    $"Sequence gap before entry #{row.Sequence} — a row was deleted or inserted.");
            }

            if (!string.Equals(row.PreviousHash, expectedPrevious, StringComparison.Ordinal))
            {
                return new AuditIntegrityReport(false, rows.Count, row.Sequence,
                    $"Entry #{row.Sequence} does not link to the previous entry — the chain was broken here.");
            }

            var recomputed = AuditRowHasher.Compute(row, expectedPrevious);
            if (!string.Equals(recomputed, row.EntryHash, StringComparison.Ordinal))
            {
                return new AuditIntegrityReport(false, rows.Count, row.Sequence,
                    $"Entry #{row.Sequence} has been altered — its hash no longer matches its content.");
            }

            expectedPrevious = row.EntryHash!;
        }

        return new AuditIntegrityReport(true, rows.Count, null, $"Chain intact — {rows.Count} entries verified.");
    }
}
