namespace EclipsVault.Core.Application.Auditing;

/// <summary>
/// One audit row as carried in an exported bundle — every field the row hash binds.
///
/// <paramref name="HashVersion"/> is last and defaulted so that a bundle exported before the field
/// existed still deserialises: it arrives as 0 and is read as version 1, which is what those rows
/// were sealed with. An auditor's older bundle must never stop verifying because we added a field.
/// </summary>
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
    string EntryHash,
    int HashVersion = AuditRowHasher.LegacyVersion);

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
