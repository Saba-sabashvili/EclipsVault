using EclipsVault.Core.Application.Abstractions;
using Xunit;

namespace EclipsVault.Tests.Security;

/// <summary>
/// SealedSecret overrides record equality so its byte[] members compare by content, not by reference.
/// Without that, two envelopes with byte-identical payloads are unequal — the trap a future set,
/// Distinct, dictionary key, or Assert.Equal would spring. These pin the content-equality contract.
/// </summary>
public class SealedSecretTests
{
    private static SealedSecret Make(
        byte[]? ciphertext = null, byte[]? wrappedDek = null, string kekId = "kek-a", string algorithm = "AES-256-GCM-AAD")
        => new(ciphertext ?? [1, 2, 3], wrappedDek ?? [4, 5, 6], kekId, algorithm);

    [Fact]
    public void Two_envelopes_with_identical_bytes_are_equal_and_hash_alike()
    {
        var a = Make();
        var b = Make(); // distinct array instances, identical contents

        Assert.Equal(a, b);
        Assert.True(a == b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void Differing_in_any_single_field_breaks_equality()
    {
        var baseline = Make();

        Assert.NotEqual(baseline, Make(ciphertext: [9, 9, 9]));
        Assert.NotEqual(baseline, Make(wrappedDek: [9, 9, 9]));
        Assert.NotEqual(baseline, Make(kekId: "kek-b"));
        Assert.NotEqual(baseline, Make(algorithm: "AES-256-GCM"));
    }

    [Fact]
    public void Equal_envelopes_deduplicate_in_a_hash_set()
    {
        var set = new HashSet<SealedSecret> { Make(), Make() };
        Assert.Single(set);
    }
}
