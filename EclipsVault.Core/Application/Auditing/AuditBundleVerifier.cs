using System.Security.Cryptography;
using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Auditing;

/// <summary>Outcome of verifying an exported audit bundle.</summary>
public sealed record AuditBundleVerification(
    bool IsValid,
    long RowsVerified,
    long? FirstBrokenSequence,
    bool SignatureValid,
    string Message);

/// <summary>
/// Verifies an <see cref="AuditBundle"/> with no dependency on the vault, its database, or its
/// private key. It (1) re-walks the hash chain, recomputing each row's hash exactly as the
/// vault did, (2) confirms the signed checkpoint matches the chain head, and (3) checks the
/// ECDSA signature against the public key embedded in the bundle. Pure BCL, so the very same
/// code runs inside the app and in the standalone <c>EclipsVault.AuditVerifier</c> tool.
/// </summary>
public static class AuditBundleVerifier
{
    public static AuditBundleVerification Verify(AuditBundle bundle)
    {
        var rows = bundle.Rows.OrderBy(r => r.Sequence).ToList();

        // (1) Re-walk the chain, recomputing every row's hash from its content + the running head.
        var previous = AuditRowHasher.GenesisHash;
        long verified = 0;
        foreach (var row in rows)
        {
            if (!string.Equals(row.PreviousHash, previous, StringComparison.Ordinal))
            {
                return Broken(row.Sequence, verified, "a row's recorded previous-hash does not continue the chain (a row was inserted, removed, or reordered)");
            }

            var recomputed = AuditRowHasher.Compute(ToAuditLog(row), row.PreviousHash);
            if (!string.Equals(recomputed, row.EntryHash, StringComparison.Ordinal))
            {
                return Broken(row.Sequence, verified, "a row's content no longer matches its recorded hash (the row was edited)");
            }

            previous = row.EntryHash;
            verified++;
        }

        // (2) The signed checkpoint must attest to the actual head of the chain in the bundle.
        var head = rows.Count == 0 ? AuditRowHasher.GenesisHash : rows[^1].EntryHash;
        var headSequence = rows.Count == 0 ? 0 : rows[^1].Sequence;
        if (bundle.Checkpoint.Sequence != headSequence ||
            !string.Equals(bundle.Checkpoint.ChainHeadHash, head, StringComparison.Ordinal))
        {
            return new AuditBundleVerification(false, verified, null, false,
                "The signed checkpoint does not match the chain head in this bundle (rows may have been dropped after signing).");
        }

        // (3) The signature must verify against the bundle's own public key.
        if (!SignatureIsValid(bundle))
        {
            return new AuditBundleVerification(false, verified, null, false,
                "The checkpoint signature is not valid for the supplied public key.");
        }

        return new AuditBundleVerification(true, verified, null, true,
            $"Chain intact across {verified} row(s); checkpoint at sequence {headSequence} is validly signed by key {bundle.Checkpoint.SigningKeyId}.");
    }

    private static bool SignatureIsValid(AuditBundle bundle)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(bundle.PublicKeySpki, out _);
            var canonical = AuditCheckpointCanonical.Bytes(
                bundle.Checkpoint.Sequence, bundle.Checkpoint.ChainHeadHash, bundle.Checkpoint.CreatedAtUtc);
            return ecdsa.VerifyData(canonical, bundle.Checkpoint.Signature, HashAlgorithmName.SHA256);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static AuditBundleVerification Broken(long sequence, long verified, string why) =>
        new(false, verified, sequence, false, $"Chain broken at sequence {sequence}: {why}.");

    private static AuditLog ToAuditLog(AuditBundleRow r) => new()
    {
        Id = r.Id,
        Sequence = r.Sequence,
        TimestampUtc = r.TimestampUtc,
        UserId = r.UserId,
        Username = r.Username,
        SourceIp = r.SourceIp,
        Action = (AuditAction)r.Action,
        ResourceType = r.ResourceType,
        ResourceId = r.ResourceId,
        ResourceName = r.ResourceName,
        Details = r.Details,
        IsCritical = r.IsCritical
    };
}
