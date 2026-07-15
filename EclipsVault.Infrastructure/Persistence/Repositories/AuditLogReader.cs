using EclipsVault.Core.Domain.Enums;
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

    public async Task<IReadOnlyList<AuditEntryDto>> ListForActorAsync(Guid actorUserId, int skip, int take, CancellationToken ct)
        => await _db.AuditLogs.AsNoTracking()
            .Where(a => a.UserId == actorUserId)
            // TimestampUtc first for the human ordering; Sequence breaks ties within the same
            // instant so paging is stable and never repeats or skips a row across pages.
            .OrderByDescending(a => a.TimestampUtc)
            .ThenByDescending(a => a.Sequence)
            .Skip(skip)
            .Take(take)
            .Select(a => new AuditEntryDto(
                a.Id, a.TimestampUtc, a.Username, a.SourceIp, a.Action,
                a.ResourceType, a.ResourceName, a.Details, a.IsCritical))
            .ToListAsync(ct);

    public async Task<IReadOnlyList<AuditEntryDto>> ListForActorByActionsAsync(
        Guid actorUserId, IReadOnlyCollection<AuditAction> actions, int take, CancellationToken ct)
    {
        if (actorUserId == Guid.Empty || actions.Count == 0 || take <= 0)
        {
            return [];
        }

        // EF translates Contains over a small in-memory set to a SQL IN (...) filter, so the
        // action restriction runs in the database rather than in memory.
        return await _db.AuditLogs.AsNoTracking()
            .Where(a => a.UserId == actorUserId && actions.Contains(a.Action))
            .OrderByDescending(a => a.TimestampUtc)
            .ThenByDescending(a => a.Sequence)
            .Take(take)
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
