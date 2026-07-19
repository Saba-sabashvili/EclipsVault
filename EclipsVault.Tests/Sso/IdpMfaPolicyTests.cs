using EclipsVault.Core.Application.Sso;
using Xunit;

namespace EclipsVault.Tests.Sso;

/// <summary>
/// Whether the vault waives its own second factor, decided from the IdP's <c>amr</c> claim.
///
/// Getting this wrong in the permissive direction is invisible: sign-in still says "success", and
/// every account is quietly worth one IdP password. So the rule is that silence, ambiguity and
/// anything unrecognised all mean "no".
/// </summary>
public class IdpMfaPolicyTests
{
    [Theory]
    [InlineData("mfa")]                  // the IdP says so outright (RFC 8176)
    [InlineData("pwd", "otp")]           // knowledge + possession
    [InlineData("pin", "hwk")]           // knowledge + hardware key
    [InlineData("pwd", "face")]          // knowledge + biometric
    [InlineData("pwd", "otp", "mfa")]
    public void Two_real_factors_count(params string[] amr)
        => Assert.True(IdpMfaPolicy.AssertedMultiFactor(amr));

    [Theory]
    [InlineData("pwd")]                  // one factor
    [InlineData("otp")]                  // one factor
    [InlineData("pwd", "pin")]           // two of the same kind is one factor twice
    [InlineData("otp", "hwk")]           // likewise
    [InlineData("kba")]                  // security questions are not a factor
    [InlineData("pwd", "kba")]
    public void One_factor_or_two_of_a_kind_does_not(params string[] amr)
        => Assert.False(IdpMfaPolicy.AssertedMultiFactor(amr));

    [Fact]
    public void Silence_is_not_assurance()
    {
        // amr is optional and most providers omit it unless configured — Keycloak included. An
        // absent claim must mean "asserted nothing", never "probably fine".
        Assert.False(IdpMfaPolicy.AssertedMultiFactor(null));
        Assert.False(IdpMfaPolicy.AssertedMultiFactor([]));
    }

    [Fact]
    public void Sms_is_not_counted_as_a_second_factor()
    {
        // Widely accepted, widely defeated by SIM swapping. This is a secrets vault; the cost of
        // refusing is one TOTP prompt, and the cost of accepting is a phone number.
        Assert.False(IdpMfaPolicy.AssertedMultiFactor(["pwd", "sms"]));
        Assert.False(IdpMfaPolicy.AssertedMultiFactor(["pwd", "tel"]));
    }

    [Fact]
    public void Unrecognised_methods_are_not_guessed_at()
    {
        Assert.False(IdpMfaPolicy.AssertedMultiFactor(["pwd", "something-new"]));
        Assert.False(IdpMfaPolicy.AssertedMultiFactor(["vendor-magic"]));
    }

    [Fact]
    public void Method_names_are_matched_regardless_of_case()
        => Assert.True(IdpMfaPolicy.AssertedMultiFactor(["PWD", "OTP"]));
}
