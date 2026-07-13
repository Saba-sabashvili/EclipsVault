using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// One immutable line of the audit trail. Rows are only ever inserted — never
/// updated or deleted through the application.
/// </summary>
public class AuditLog
{
    public Guid Id { get; set; }

    public DateTimeOffset TimestampUtc { get; set; }

    public Guid? UserId { get; set; }

    public string Username { get; set; } = "system";

    public string SourceIp { get; set; } = "internal";

    public AuditAction Action { get; set; }

    public string ResourceType { get; set; } = string.Empty;

    public Guid? ResourceId { get; set; }

    public string? ResourceName { get; set; }

    public string? Details { get; set; }

    /// <summary>High-priority entries (honey-token trips, forced revocations).</summary>
    public bool IsCritical { get; set; }

    // ---- Tamper-evidence (hash chain) --------------------------------------------
    // Each row commits to the one before it: EntryHash = SHA-256(this row's content ||
    // PreviousHash). Any insert, edit, delete, or reorder breaks the chain and is caught
    // by the integrity verification. Sequence is the monotonic position in the chain.

    /// <summary>Monotonic position in the audit chain (1-based). 0 means not yet chained.</summary>
    public long Sequence { get; set; }

    /// <summary>The <see cref="EntryHash"/> of the preceding row (or the genesis hash for the first).</summary>
    public string? PreviousHash { get; set; }

    /// <summary>This row's hash: SHA-256 over its immutable content and <see cref="PreviousHash"/>.</summary>
    public string? EntryHash { get; set; }
}
