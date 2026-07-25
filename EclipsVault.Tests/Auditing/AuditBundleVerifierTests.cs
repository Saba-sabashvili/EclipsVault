using System.Security.Cryptography;
using EclipsVault.Core.Application.Auditing;
using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Enums;
using Xunit;

namespace EclipsVault.Tests.Auditing;

/// <summary>
/// End-to-end properties of the externally verifiable audit bundle: a genuine bundle verifies,
/// and every class of tampering an attacker with database access might attempt is rejected.
/// </summary>
public class AuditBundleVerifierTests
{
    // ---- Builders: produce a correctly chained + signed bundle, mirroring the vault ----------

    private static AuditBundleRow Row(long seq, string previousHash, string details)
    {
        var log = new AuditLog
        {
            Id = Guid.NewGuid(),
            Sequence = seq,
            TimestampUtc = DateTimeOffset.UnixEpoch.AddMinutes(seq),
            UserId = Guid.NewGuid(),
            Username = "alice",
            SourceIp = "10.0.0.1",
            Action = AuditAction.SecretRevealed,
            ResourceType = "Secret",
            ResourceName = "Phoenix_Staging_Api_Key",
            Details = details,
            IsCritical = false,
            PreviousHash = previousHash
        };
        var entryHash = AuditRowHasher.Compute(log, previousHash);
        return new AuditBundleRow(
            log.Sequence, log.Id, log.TimestampUtc, log.UserId, log.Username, log.SourceIp,
            (int)log.Action, log.ResourceType, log.ResourceId, log.ResourceName, log.Details,
            log.IsCritical, previousHash, entryHash);
    }

    private static List<AuditBundleRow> Chain(int count, string tag = "row")
    {
        var rows = new List<AuditBundleRow>();
        var previous = AuditRowHasher.GenesisHash;
        for (var i = 1; i <= count; i++)
        {
            var row = Row(i, previous, $"{tag} {i}");
            rows.Add(row);
            previous = row.EntryHash;
        }

        return rows;
    }

    private static AuditBundle Bundle(List<AuditBundleRow> rows, ECDsa signingKey)
    {
        var headSeq = rows.Count == 0 ? 0 : rows[^1].Sequence;
        var headHash = rows.Count == 0 ? AuditRowHasher.GenesisHash : rows[^1].EntryHash;
        var createdAt = DateTimeOffset.UnixEpoch.AddHours(1);
        var signature = signingKey.SignData(
            AuditCheckpointCanonical.Bytes(headSeq, headHash, createdAt), HashAlgorithmName.SHA256);

        return new AuditBundle(
            "eclipsvault.audit-bundle/1",
            createdAt,
            signingKey.ExportSubjectPublicKeyInfo(),
            new AuditBundleCheckpoint(headSeq, headHash, createdAt, "sig-test", signature),
            rows);
    }

    // ---- Tests ------------------------------------------------------------------------------

    [Fact]
    public void A_genuine_bundle_verifies()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var result = AuditBundleVerifier.Verify(Bundle(Chain(5), key));

        Assert.True(result.IsValid);
        Assert.True(result.SignatureValid);
        Assert.Equal(5, result.RowsVerified);
    }

    [Fact]
    public void An_empty_but_signed_bundle_verifies()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var result = AuditBundleVerifier.Verify(Bundle([], key));
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Editing_a_row_after_signing_is_rejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rows = Chain(5);
        // Attacker edits row 3's content but leaves its recorded hash — the recompute won't match.
        rows[2] = rows[2] with { Details = "TAMPERED" };

        var result = AuditBundleVerifier.Verify(Bundle(rows, key));

        Assert.False(result.IsValid);
        Assert.Equal(3, result.FirstBrokenSequence);
    }

    [Fact]
    public void Dropping_the_last_row_after_signing_is_rejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rows = Chain(5);
        var bundle = Bundle(rows, key);

        // Attacker removes the final row but keeps the checkpoint that was signed over the full chain.
        var truncated = bundle with { Rows = rows.Take(4).ToList() };

        var result = AuditBundleVerifier.Verify(truncated);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void A_signature_from_a_different_key_is_rejected()
    {
        using var realKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rows = Chain(3);

        // Sign with the attacker's key but present the real (unrelated) public key.
        var forged = Bundle(rows, attackerKey) with { PublicKeySpki = realKey.ExportSubjectPublicKeyInfo() };

        var result = AuditBundleVerifier.Verify(forged);
        Assert.False(result.IsValid);
        Assert.False(result.SignatureValid);
    }

    [Fact]
    public void A_fully_rewritten_chain_cannot_be_resigned_and_is_rejected()
    {
        using var realKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var genuine = Bundle(Chain(5), realKey);

        // The attacker rewrites history into a *different but internally consistent* chain —
        // they can recompute every hash, since the hash function is public. What they cannot do
        // is forge a signature over the new head without the private key, so they are stuck with
        // the original checkpoint, which no longer matches the rewritten chain.
        var rewritten = genuine with { Rows = Chain(5, tag: "evil") };

        var result = AuditBundleVerifier.Verify(rewritten);
        Assert.False(result.IsValid);
    }

    // ---- Key pinning ------------------------------------------------------------------------
    // The gap pinning closes: an insider who holds no private key can still mint a wholly new,
    // internally consistent chain, sign it with a keypair THEY generated, and embed that public
    // key. Every self-consistency check passes. Only pinning the key the auditor trusts rejects it.

    [Fact]
    public void A_rewritten_chain_resigned_with_the_attackers_own_key_verifies_when_unpinned()
    {
        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Freshly forged chain, signed by and carrying the attacker's own public key.
        var forged = Bundle(Chain(5, tag: "forged"), attackerKey);

        // Unpinned, this is "valid" — which is exactly why a pinned key is necessary.
        Assert.True(AuditBundleVerifier.Verify(forged).IsValid);
    }

    [Fact]
    public void A_rewritten_chain_resigned_with_the_attackers_own_key_is_rejected_when_the_key_is_pinned()
    {
        using var realKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var forged = Bundle(Chain(5, tag: "forged"), attackerKey);

        var result = AuditBundleVerifier.Verify(forged, realKey.ExportSubjectPublicKeyInfo());
        Assert.False(result.IsValid);
        Assert.False(result.SignatureValid);
    }

    [Fact]
    public void A_genuine_bundle_verifies_when_the_correct_key_is_pinned()
    {
        using var realKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var genuine = Bundle(Chain(5), realKey);

        var result = AuditBundleVerifier.Verify(genuine, realKey.ExportSubjectPublicKeyInfo());
        Assert.True(result.IsValid);
        Assert.True(result.SignatureValid);
        Assert.Equal(5, result.RowsVerified);
    }

    [Fact]
    public void Pinning_a_different_key_rejects_an_otherwise_genuine_bundle()
    {
        using var realKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var genuine = Bundle(Chain(5), realKey);

        var result = AuditBundleVerifier.Verify(genuine, otherKey.ExportSubjectPublicKeyInfo());
        Assert.False(result.IsValid);
    }

    /// <summary>
    /// A checkpoint's SigningKeyId is not covered by the signature, so a bundle can be edited to
    /// name any key without breaking verification. The id an auditor is shown must therefore be
    /// derived from the public key that actually verified the signature — otherwise the one piece of
    /// provenance a human reads off the report is the one piece an attacker can choose.
    /// </summary>
    [Fact]
    public void The_reported_key_id_is_derived_from_the_key_that_signed_not_the_stored_label()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var expected = AuditSigningKeyId.For(key.ExportSubjectPublicKeyInfo());

        var bundle = Bundle(Chain(3), key);
        var mislabelled = bundle with
        {
            Checkpoint = bundle.Checkpoint with { SigningKeyId = "sig-deadbeef" }
        };

        var result = AuditBundleVerifier.Verify(mislabelled);

        // Still valid — the label was never part of the signed material.
        Assert.True(result.IsValid);
        // But the report names the real key, and says the label disagreed.
        Assert.Contains(expected, result.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("validly signed by key sig-deadbeef", result.Message, StringComparison.Ordinal);
        Assert.Contains("not covered by the signature", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_correctly_labelled_bundle_reports_no_discrepancy()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyId = AuditSigningKeyId.For(key.ExportSubjectPublicKeyInfo());

        var bundle = Bundle(Chain(3), key);
        var labelled = bundle with { Checkpoint = bundle.Checkpoint with { SigningKeyId = keyId } };

        var result = AuditBundleVerifier.Verify(labelled);

        Assert.True(result.IsValid);
        Assert.Contains(keyId, result.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("NOTE:", result.Message, StringComparison.Ordinal);
    }
}
