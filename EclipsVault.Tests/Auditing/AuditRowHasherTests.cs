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
}
