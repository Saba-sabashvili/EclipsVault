using System.Security.Cryptography;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.LicenseForge.Commands;
using Xunit;

namespace EclipsVault.Tests.Licensing;

public class MintClaimsTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 6, 12, 0, 0, TimeSpan.Zero);

    private static MintClaims.Result Build(
        string? tier = "Max", int? trialDays = null, int expiresYears = 0, string? issuedTo = "Acme Ltd")
        => MintClaims.Build(
            tierText: tier,
            issuedTo: issuedTo,
            contact: null,
            licenseId: "lic-001",
            nodes: 1,
            updateYears: 1,
            features: [],
            expiresYears: expiresYears,
            trialDays: trialDays,
            now: Now);

    [Fact]
    public void A_trial_mints_a_max_licence_expiring_after_the_window()
    {
        var result = Build(tier: null, trialDays: 30);

        Assert.True(result.Ok);
        Assert.Equal(LicenseTier.Max, result.Claims!.Tier);
        Assert.Equal(Now.AddDays(30), result.Claims.NotAfterUtc);
    }

    [Fact]
    public void A_trial_token_verifies_now_and_lapses_after_its_window()
    {
        var result = Build(tier: null, trialDays: 30);
        Assert.True(result.Ok);

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = LicenseSigner.Sign(result.Claims!, key);
        var spki = key.ExportSubjectPublicKeyInfo();

        // Valid inside the window, Expired once it elapses — the whole point of a trial, and it needs
        // no runtime change: the verifier already returns Expired past NotAfterUtc.
        Assert.Equal(LicenseStatus.Valid, LicenseVerifier.Verify(token, spki, Now).Status);
        Assert.Equal(LicenseStatus.Valid, LicenseVerifier.Verify(token, spki, Now.AddDays(29)).Status);
        Assert.Equal(LicenseStatus.Expired, LicenseVerifier.Verify(token, spki, Now.AddDays(31)).Status);
    }

    [Fact]
    public void Trial_days_sets_the_window_length()
    {
        var result = Build(tier: null, trialDays: 14);

        Assert.True(result.Ok);
        Assert.Equal(Now.AddDays(14), result.Claims!.NotAfterUtc);
    }

    [Fact]
    public void A_trial_refuses_a_non_max_tier()
    {
        var result = Build(tier: "Community", trialDays: 30);

        Assert.False(result.Ok);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public void A_trial_cannot_be_combined_with_a_years_expiry()
    {
        var result = Build(tier: null, trialDays: 30, expiresYears: 2);

        Assert.False(result.Ok);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void Trial_days_must_be_positive(int days)
    {
        var result = Build(tier: null, trialDays: days);

        Assert.False(result.Ok);
    }

    [Fact]
    public void A_normal_max_licence_stays_perpetual()
    {
        var result = Build(tier: "Max");

        Assert.True(result.Ok);
        Assert.Null(result.Claims!.NotAfterUtc);
        Assert.Equal(Now.AddYears(1), result.Claims.UpdatesUntilUtc);
    }

    [Fact]
    public void The_tier_is_required_when_not_a_trial()
    {
        var result = Build(tier: null);

        Assert.False(result.Ok);
    }

    [Fact]
    public void The_customer_name_is_required()
    {
        var result = Build(tier: "Max", issuedTo: "  ");

        Assert.False(result.Ok);
    }

    [Fact]
    public void A_negative_expiry_is_refused_rather_than_read_as_perpetual()
    {
        var result = Build(expiresYears: -1);

        Assert.False(result.Ok);
        Assert.Contains("--expires", result.Error!);
    }
}
