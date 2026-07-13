namespace EclipsVault.Core.Application.Auditing;

/// <summary>A persisted checkpoint, for display.</summary>
public sealed record AuditCheckpointDto(long Sequence, string ChainHeadHash, DateTimeOffset CreatedAtUtc, string SigningKeyId);

/// <summary>
/// Creates signed checkpoints over the audit hash chain and produces a portable, externally
/// verifiable export bundle. Signing turns the trail from "tamper-evident to anyone with the
/// database" into "tamper-evident to anyone with the public key."
/// </summary>
public interface IAuditCheckpointService
{
    /// <summary>Signs the current chain head and persists a checkpoint. Returns null if nothing is chained yet.</summary>
    Task<AuditCheckpointDto?> CreateCheckpointAsync(CancellationToken ct);

    /// <summary>The most recent checkpoint, or null if none has been created.</summary>
    Task<AuditCheckpointDto?> GetLatestAsync(CancellationToken ct);

    /// <summary>Short identifier of the active signing key (for display).</summary>
    string SigningKeyId { get; }

    /// <summary>
    /// Builds a self-contained bundle — all chained rows, a fresh signed checkpoint over the
    /// current head, and the public key — ready to serialize and hand to an external auditor.
    /// </summary>
    Task<AuditBundle> ExportAsync(CancellationToken ct);
}
