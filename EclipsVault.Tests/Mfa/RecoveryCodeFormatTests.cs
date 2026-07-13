using EclipsVault.Core.Application.Mfa;
using Xunit;

namespace EclipsVault.Tests.Mfa;

public class RecoveryCodeFormatTests
{
    [Fact]
    public void NewCode_is_two_groups_of_five_from_the_safe_alphabet()
        => Assert.Matches("^[A-Z2-9]{5}-[A-Z2-9]{5}$", RecoveryCodeFormat.NewCode());

    [Fact]
    public void NewCode_never_emits_visually_ambiguous_characters()
    {
        for (var i = 0; i < 500; i++)
        {
            var normalized = RecoveryCodeFormat.Normalize(RecoveryCodeFormat.NewCode());
            Assert.False(normalized.Any(c => c is 'I' or 'O' or '0' or '1'),
                $"'{normalized}' contained an ambiguous character");
        }
    }

    [Fact]
    public void Normalize_strips_separators_and_whitespace_and_uppercases()
        => Assert.Equal("ABCDEFGHJK", RecoveryCodeFormat.Normalize("  abcde-fghjk "));

    [Fact]
    public void Normalize_of_a_new_code_is_exactly_ten_characters()
        => Assert.Equal(10, RecoveryCodeFormat.Normalize(RecoveryCodeFormat.NewCode()).Length);

    [Fact]
    public void The_displayed_code_and_the_typed_back_code_normalize_identically()
    {
        var display = RecoveryCodeFormat.NewCode();               // e.g. "ABCDE-FGHJK"
        var typedBack = display.ToLowerInvariant().Replace("-", " ");
        Assert.Equal(RecoveryCodeFormat.Normalize(display), RecoveryCodeFormat.Normalize(typedBack));
    }

    [Fact]
    public void Codes_are_effectively_unique_per_generation()
    {
        var codes = Enumerable.Range(0, 1000).Select(_ => RecoveryCodeFormat.NewCode()).ToHashSet();
        Assert.True(codes.Count > 995, "recovery codes should not collide in a small batch");
    }
}
