using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Auditing;

public sealed record AuditEntryDto(
    Guid Id,
    DateTimeOffset TimestampUtc,
    string Username,
    string SourceIp,
    AuditAction Action,
    string ResourceType,
    string? ResourceName,
    string? Details,
    bool IsCritical);

/// <summary>Outcome of verifying the audit hash chain.</summary>
public sealed record AuditIntegrityReport(bool Intact, long ChainedRows, long? FirstBrokenSequence, string Message);

/// <summary>Read-only access to the audit trail for dashboards and the audit viewer.</summary>
public interface IAuditLogReader
{
    /// <summary>Latest entries, newest first; optionally restricted to one actor.</summary>
    Task<IReadOnlyList<AuditEntryDto>> ListRecentAsync(int count, string? username, CancellationToken ct);

    Task<int> CountCriticalSinceAsync(DateTimeOffset sinceUtc, CancellationToken ct);

    /// <summary>Re-walks the hash chain and reports whether it is intact, pinpointing the first broken row.</summary>
    Task<AuditIntegrityReport> VerifyIntegrityAsync(CancellationToken ct);
}
