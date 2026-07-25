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
/// vault did, (2) confirms the signed checkpoint matches the chain head, (3) — when the caller
/// supplies one — checks the bundle's embedded public key against a pinned expected key, and
/// (4) checks the ECDSA signature. Pure BCL, so the very same code runs inside the app and in
/// the standalone <c>EclipsVault.AuditVerifier</c> tool.
///
/// Pinning matters: without an expected key, a valid result proves only that the bundle is
/// internally self-consistent and signed by <em>whatever</em> key it carries. An insider who
/// rewrote the chain and re-signed it with their own keypair — embedding their own public key —
/// would pass every other check. Pinning the key the auditor obtained out-of-band is what turns
/// "internally consistent" into "signed by the vault's key".
/// </summary>
public static class AuditBundleVerifier
{
    /// <summary>Verifies a bundle for self-consistency and a valid signature by its own embedded key.</summary>
    public static AuditBundleVerification Verify(AuditBundle bundle) => Verify(bundle, expectedPublicKeySpki: null);

    /// <summary>
    /// Verifies a bundle and, when <paramref name="expectedPublicKeySpki"/> is supplied, additionally
    /// requires that the bundle's embedded public key is exactly that key (SubjectPublicKeyInfo bytes).
    /// </summary>
    public static AuditBundleVerification Verify(AuditBundle bundle, byte[]? expectedPublicKeySpki)
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

        // (3) When a key is pinned, the bundle's embedded key must be exactly it — otherwise a
        // chain rewritten and re-signed with an attacker's own keypair would still verify at (4).
        if (expectedPublicKeySpki is not null &&
            !CryptographicOperations.FixedTimeEquals(bundle.PublicKeySpki, expectedPublicKeySpki))
        {
            return new AuditBundleVerification(false, verified, null, false,
                "The bundle's signing key does not match the expected key. The trail may have been rewritten and re-signed with a different key.");
        }

        // (4) The signature must verify against the bundle's own public key (now pinned, if supplied).
        if (!SignatureIsValid(bundle))
        {
            return new AuditBundleVerification(false, verified, null, false,
                "The checkpoint signature is not valid for the supplied public key.");
        }

        var trust = expectedPublicKeySpki is null
            ? "(unpinned — this proves the bundle is self-consistent and signed by its own embedded key, not that the key is the vault's)"
            : "(key pinned to the expected value)";

        // Report the id derived from the key that actually verified the signature, not the one the
        // bundle claims: SigningKeyId is not covered by the signature, so an edited bundle could
        // name any key. A disagreement is worth surfacing — nothing legitimate produces one.
        var keyId = AuditSigningKeyId.For(bundle.PublicKeySpki);
        var claimed = string.Equals(bundle.Checkpoint.SigningKeyId, keyId, StringComparison.Ordinal)
            ? string.Empty
            : $" NOTE: the bundle labels this key '{bundle.Checkpoint.SigningKeyId}', which is not the id of the key that signed it — that label is not covered by the signature and has been edited or was written by an older build.";

        return new AuditBundleVerification(true, verified, null, true,
            $"Chain intact across {verified} row(s); checkpoint at sequence {headSequence} is validly signed by key {keyId} {trust}.{claimed}");
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
        IsCritical = r.IsCritical,
        // 0 means the bundle predates the field; those rows were sealed under version 1.
        HashVersion = r.HashVersion == 0 ? AuditRowHasher.LegacyVersion : r.HashVersion
    };
}
