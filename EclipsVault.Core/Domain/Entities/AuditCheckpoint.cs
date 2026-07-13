namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// A signed attestation of the audit hash chain at a point in time. It binds the chain head
/// (sequence + hash) with an asymmetric signature, so an external party holding only the
/// public key can prove the trail has not been rewritten — even by someone with full database
/// access who deleted rows and recomputed every remaining hash: they cannot forge the
/// signature over a head they did not have signed.
/// </summary>
public class AuditCheckpoint
{
    public Guid Id { get; set; }

    /// <summary>Chain position this checkpoint attests to (the head sequence at creation).</summary>
    public long Sequence { get; set; }

    /// <summary>The chain head hash (the <c>EntryHash</c> of row <see cref="Sequence"/>) that was signed.</summary>
    public string ChainHeadHash { get; set; } = string.Empty;

    public DateTimeOffset CreatedAtUtc { get; set; }

    /// <summary>ECDSA (P-256 / SHA-256) signature over the canonical checkpoint bytes.</summary>
    public byte[] Signature { get; set; } = [];

    /// <summary>Short identifier (thumbprint) of the signing key, for display and key rotation.</summary>
    public string SigningKeyId { get; set; } = string.Empty;
}
