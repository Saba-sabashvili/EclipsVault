namespace EclipsVault.Core.Application.Auditing;

/// <summary>One audit row as carried in an exported bundle — every field the row hash binds.</summary>
public sealed record AuditBundleRow(
    long Sequence,
    Guid Id,
    DateTimeOffset TimestampUtc,
    Guid? UserId,
    string Username,
    string SourceIp,
    int Action,
    string ResourceType,
    Guid? ResourceId,
    string? ResourceName,
    string? Details,
    bool IsCritical,
    string PreviousHash,
    string EntryHash);

/// <summary>The signed checkpoint as carried in a bundle.</summary>
public sealed record AuditBundleCheckpoint(
    long Sequence,
    string ChainHeadHash,
    DateTimeOffset CreatedAtUtc,
    string SigningKeyId,
    byte[] Signature);

/// <summary>
/// A self-contained, externally verifiable export of the audit trail: every chained row, a
/// signed checkpoint over the head, and the public key needed to verify the signature. It can
/// be handed to an auditor and checked with <see cref="AuditBundleVerifier"/> (or the
/// standalone tool) without any access to the vault, its database, or its private key.
/// </summary>
public sealed record AuditBundle(
    string SchemaVersion,
    DateTimeOffset ExportedAtUtc,
    byte[] PublicKeySpki,
    AuditBundleCheckpoint Checkpoint,
    IReadOnlyList<AuditBundleRow> Rows);
