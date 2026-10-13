using EclipsVault.LicenseForge.Cli;
using Xunit;

namespace EclipsVault.Tests.Licensing;

/// <summary>
/// The mint flags decide how much authority a licence carries, and a licence cannot be revoked once
/// it reaches a customer — so every one of these asserts that a malformed flag is <em>refused</em>
/// rather than quietly dropped. A dropped flag used to fall back to the most generous value there is
/// (no expiry, unlimited nodes), which meant a typo minted a perpetual licence and said so in green.
/// </summary>
public class CommandLineOptionsTests
{
    private static readonly string[] Known = ["key-file", "tier", "to", "expires", "trial-days", "nodes"];

    private static CommandLineOptions.ParseResult Parse(params string[] args)
        => CommandLineOptions.Parse(args, Known);

    [Fact]
    public void A_flag_and_its_value_are_read_as_a_pair()
    {
        var result = Parse("mint", "--tier", "Max", "--to", "Acme Ltd");

        Assert.True(result.Ok, result.Error);
        Assert.Equal("Max", result.Options!.Get("tier"));
        Assert.Equal("Acme Ltd", result.Options.Get("to"));
    }

    [Fact]
    public void The_equals_form_is_read_as_a_flag_and_value_not_as_an_unknown_flag()
    {
        var result = Parse("mint", "--tier", "Max", "--expires=1");

        Assert.True(result.Ok, result.Error);
        Assert.Equal(1, result.Options!.GetInt("expires").Value);
    }

    [Fact]
    public void A_flag_whose_value_was_dropped_is_refused_rather_than_ignored()
    {
        var result = Parse("mint", "--tier", "Max", "--trial-days");

        Assert.False(result.Ok);
        Assert.Contains("trial-days", result.Error!);
    }

    [Fact]
    public void An_unknown_flag_is_refused_rather_than_accepted_in_silence()
    {
        var result = Parse("mint", "--tier", "Max", "--totally-bogus", "5");

        Assert.False(result.Ok);
        Assert.Contains("totally-bogus", result.Error!);
    }

    [Fact]
    public void A_number_that_will_not_parse_is_an_error_not_a_fallback_to_zero()
    {
        var result = Parse("mint", "--expires", "1yr");
        Assert.True(result.Ok, result.Error);

        var expires = result.Options!.GetInt("expires");

        Assert.False(expires.Ok);
        Assert.Contains("expires", expires.Error!);
    }

    [Fact]
    public void A_negative_number_is_an_error_rather_than_a_silently_generous_one()
    {
        var result = Parse("mint", "--expires", "-1");
        Assert.True(result.Ok, result.Error);

        var expires = result.Options!.GetInt("expires");

        Assert.False(expires.Ok);
        Assert.Contains("expires", expires.Error!);
    }

    [Fact]
    public void An_absent_number_flag_is_not_an_error()
    {
        var result = Parse("mint", "--tier", "Max");
        Assert.True(result.Ok, result.Error);

        var expires = result.Options!.GetInt("expires");

        Assert.True(expires.Ok, expires.Error);
        Assert.Null(expires.Value);
    }

    [Fact]
    public void A_repeated_flag_takes_the_last_value()
    {
        var result = Parse("mint", "--tier", "Community", "--tier", "Max");

        Assert.True(result.Ok, result.Error);
        Assert.Equal("Max", result.Options!.Get("tier"));
    }

    [Fact]
    public void A_bare_word_that_is_not_a_flag_is_refused()
    {
        var result = Parse("mint", "Max");

        Assert.False(result.Ok);
    }
}
