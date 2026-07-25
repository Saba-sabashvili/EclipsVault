using EclipsVault.Core.Application.Auditing;
using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Enums;
using Xunit;

namespace EclipsVault.Tests.Auditing;

/// <summary>Tamper-evidence properties of the audit hash chain.</summary>
public class AuditRowHasherTests
{
    private static AuditLog Row(long sequence = 1, string? details = null) => new()
    {
        Id = Guid.Parse("11111111-1111-1111-1111-111111111111"),
        Sequence = sequence,
        TimestampUtc = DateTimeOffset.UnixEpoch,
        UserId = Guid.Parse("22222222-2222-2222-2222-222222222222"),
        Username = "alice",
        SourceIp = "10.0.0.1",
        Action = AuditAction.SecretRevealed,
        ResourceType = "Secret",
        ResourceId = Guid.Parse("33333333-3333-3333-3333-333333333333"),
        ResourceName = "Phoenix_Staging_Api_Key",
        Details = details,
        IsCritical = false
    };

    [Fact]
    public void Genesis_hash_is_sixty_four_zeros()
        => Assert.Equal(new string('0', 64), AuditRowHasher.GenesisHash);

    [Fact]
    public void Compute_is_deterministic()
    {
        var a = AuditRowHasher.Compute(Row(), AuditRowHasher.GenesisHash);
        var b = AuditRowHasher.Compute(Row(), AuditRowHasher.GenesisHash);
        Assert.Equal(a, b);
    }

    [Fact]
    public void Compute_returns_a_lowercase_sha256_hex_string()
    {
        var hash = AuditRowHasher.Compute(Row(), AuditRowHasher.GenesisHash);
        Assert.Equal(64, hash.Length);
        Assert.Equal(hash.ToLowerInvariant(), hash);
    }

    [Fact]
    public void Altering_any_field_changes_the_hash()
    {
        var original = AuditRowHasher.Compute(Row(details: "before"), AuditRowHasher.GenesisHash);
        var tampered = AuditRowHasher.Compute(Row(details: "after"), AuditRowHasher.GenesisHash);
        Assert.NotEqual(original, tampered);
    }

    [Fact]
    public void Hash_binds_the_previous_hash_so_reordering_breaks_the_chain()
    {
        var afterGenesis = AuditRowHasher.Compute(Row(2), AuditRowHasher.GenesisHash);
        var afterDifferentParent = AuditRowHasher.Compute(Row(2), new string('a', 64));
        Assert.NotEqual(afterGenesis, afterDifferentParent);
    }

    [Fact]
    public void A_three_link_chain_reverifies_intact_but_fails_after_a_mid_chain_edit()
    {
        var r1 = Row(1, "one");
        var r2 = Row(2, "two");
        var r3 = Row(3, "three");

        r1.PreviousHash = AuditRowHasher.GenesisHash;
        r1.EntryHash = AuditRowHasher.Compute(r1, r1.PreviousHash);
        r2.PreviousHash = r1.EntryHash;
        r2.EntryHash = AuditRowHasher.Compute(r2, r2.PreviousHash);
        r3.PreviousHash = r2.EntryHash;
        r3.EntryHash = AuditRowHasher.Compute(r3, r3.PreviousHash);

        // Intact: recomputing each row from its stored PreviousHash reproduces its stored EntryHash.
        Assert.Equal(r1.EntryHash, AuditRowHasher.Compute(r1, r1.PreviousHash));
        Assert.Equal(r2.EntryHash, AuditRowHasher.Compute(r2, r2.PreviousHash));
        Assert.Equal(r3.EntryHash, AuditRowHasher.Compute(r3, r3.PreviousHash));

        // Tamper with row 2's content: its own recomputed hash no longer matches what row 3 committed to.
        r2.Details = "TAMPERED";
        var recomputed2 = AuditRowHasher.Compute(r2, r2.PreviousHash);
        Assert.NotEqual(r2.EntryHash, recomputed2);
        Assert.NotEqual(recomputed2, r3.PreviousHash);
    }

    // ---- canonical-form versioning -------------------------------------------------------------

    private const string Sep = ""; // the ASCII unit separator v1 joined fields with

    /// <summary>
    /// The v1 flaw, pinned so it can never be reintroduced. v1 joined fields with a separator and
    /// assumed no field contained it — nothing enforced that. Content shifted across the
    /// ResourceName/Details boundary produces a byte-identical canonical string, so two audit rows
    /// that *say different things* share a hash and a tampered row still verifies. Reachable in
    /// practice: an identity provider's email flows into Details, ResourceName and Username.
    /// </summary>
    [Fact]
    public void Version_1_collides_when_a_field_carries_the_separator_and_version_2_does_not()
    {
        var a = Row(details: "b" + Sep + "c");
        a.ResourceName = "a";

        var b = Row(details: "c");
        b.ResourceName = "a" + Sep + "b";

        // v1: "…a|b|c…" either way — the boundary moved but the bytes did not.
        Assert.Equal(
            AuditRowHasher.ComputeV1(a, AuditRowHasher.GenesisHash),
            AuditRowHasher.ComputeV1(b, AuditRowHasher.GenesisHash));

        // v2 length-prefixes every field, so the two are distinguishable.
        Assert.NotEqual(
            AuditRowHasher.ComputeV2(a, AuditRowHasher.GenesisHash),
            AuditRowHasher.ComputeV2(b, AuditRowHasher.GenesisHash));
    }

    [Fact]
    public void Compute_uses_the_scheme_the_row_declares()
    {
        var legacy = Row(details: "x");
        legacy.HashVersion = AuditRowHasher.LegacyVersion;
        Assert.Equal(
            AuditRowHasher.ComputeV1(legacy, AuditRowHasher.GenesisHash),
            AuditRowHasher.Compute(legacy, AuditRowHasher.GenesisHash));

        var current = Row(details: "x");
        current.HashVersion = AuditRowHasher.CurrentVersion;
        Assert.Equal(
            AuditRowHasher.ComputeV2(current, AuditRowHasher.GenesisHash),
            AuditRowHasher.Compute(current, AuditRowHasher.GenesisHash));

        // The two schemes must not agree, or the version would be decorative.
        Assert.NotEqual(
            AuditRowHasher.Compute(legacy, AuditRowHasher.GenesisHash),
            AuditRowHasher.Compute(current, AuditRowHasher.GenesisHash));
    }

    /// <summary>
    /// A row carrying no version — read from a database written before the column existed, or from
    /// a bundle exported before the field existed — must verify as v1, which is how it was sealed.
    /// If this regressed, every historical chain would report as tampered on upgrade.
    /// </summary>
    [Fact]
    public void An_unversioned_row_verifies_as_version_1()
    {
        var row = Row(details: "x");
        row.HashVersion = 0;

        Assert.Equal(
            AuditRowHasher.ComputeV1(row, AuditRowHasher.GenesisHash),
            AuditRowHasher.Compute(row, AuditRowHasher.GenesisHash));
    }

    [Fact]
    public void Version_2_binds_the_version_itself()
    {
        // Two rows identical but for their declared version must not share a hash, so a v2 row
        // cannot be replayed as a v1 one.
        var row = Row(details: "x");
        var v1 = AuditRowHasher.ComputeV1(row, AuditRowHasher.GenesisHash);
        var v2 = AuditRowHasher.ComputeV2(row, AuditRowHasher.GenesisHash);
        Assert.NotEqual(v1, v2);
    }
}
