using EclipsVault.Core.Application.SecurityCheckup;
using Xunit;

namespace EclipsVault.Tests.SecurityCheckupTests;

/// <summary>
/// The whole scoring model lives in the pure evaluator, so it can be pinned here without any I/O.
/// These tests lock the weighting (a secured account is 100/Strong), the status each control takes
/// for a given posture, the grade thresholds, and that the list is ranked most-urgent-first.
/// </summary>
public class SecurityCheckupEvaluatorTests
{
    private static SecurityCheck Check(SecurityCheckup c, SecurityCheckKind kind)
        => c.Checks.Single(x => x.Kind == kind);

    [Fact]
    public void A_fully_secured_account_scores_100_and_is_all_clear()
    {
        var result = SecurityCheckupEvaluator.Evaluate(
            new SecurityPosture(TwoStepEnabled: true, PasskeyCount: 2, BackupCodesRemaining: 10, SignedInDeviceCount: 1));

        Assert.Equal(100, result.Score);
        Assert.Equal(SecurityGrade.Strong, result.Grade);
        Assert.True(result.AllClear);
        Assert.Null(result.TopPriority);
        Assert.All(result.Checks, c => Assert.Equal(SecurityCheckStatus.Pass, c.Status));
    }

    [Fact]
    public void A_password_only_account_flags_two_step_first_and_is_at_risk()
    {
        var result = SecurityCheckupEvaluator.Evaluate(
            new SecurityPosture(TwoStepEnabled: false, PasskeyCount: 0, BackupCodesRemaining: 0, SignedInDeviceCount: 1));

        // TwoStep 0 + BackupCodes(recommended) 12.5 + Passkey(recommended) 10 + Devices(pass) 15 = 37.5 → 38.
        Assert.Equal(38, result.Score);
        Assert.Equal(SecurityGrade.AtRisk, result.Grade);
        Assert.Equal(SecurityCheckStatus.ActionNeeded, Check(result, SecurityCheckKind.TwoStepSignIn).Status);
        Assert.Equal(SecurityCheckKind.TwoStepSignIn, result.TopPriority!.Kind);
    }

    [Fact]
    public void With_two_step_on_no_backup_codes_is_action_needed()
    {
        var result = SecurityCheckupEvaluator.Evaluate(
            new SecurityPosture(TwoStepEnabled: true, PasskeyCount: 1, BackupCodesRemaining: 0, SignedInDeviceCount: 1));

        var backup = Check(result, SecurityCheckKind.BackupCodes);
        Assert.Equal(SecurityCheckStatus.ActionNeeded, backup.Status);
        Assert.Equal(RemediationArea.BackupCodes, backup.Fix);
        // Only control not passing → it's the top priority. 40 + 0 + 20 + 15 = 75 → Good.
        Assert.Equal(75, result.Score);
        Assert.Equal(SecurityGrade.Good, result.Grade);
        Assert.Equal(SecurityCheckKind.BackupCodes, result.TopPriority!.Kind);
    }

    [Fact]
    public void Backup_codes_are_only_recommended_until_two_step_is_on()
    {
        var result = SecurityCheckupEvaluator.Evaluate(
            new SecurityPosture(TwoStepEnabled: false, PasskeyCount: 0, BackupCodesRemaining: 0, SignedInDeviceCount: 1));

        // Without two-step, "no backup codes" must not pile on a second red mark.
        var backup = Check(result, SecurityCheckKind.BackupCodes);
        Assert.Equal(SecurityCheckStatus.Recommended, backup.Status);
        Assert.Equal(RemediationArea.Profile, backup.Fix);
    }

    [Fact]
    public void A_running_low_backup_set_is_recommended_not_critical()
    {
        var result = SecurityCheckupEvaluator.Evaluate(
            new SecurityPosture(TwoStepEnabled: true, PasskeyCount: 1, BackupCodesRemaining: 2, SignedInDeviceCount: 1));

        Assert.Equal(SecurityCheckStatus.Recommended, Check(result, SecurityCheckKind.BackupCodes).Status);
    }

    [Fact]
    public void A_missing_passkey_is_a_recommendation_and_still_allows_a_strong_grade()
    {
        var result = SecurityCheckupEvaluator.Evaluate(
            new SecurityPosture(TwoStepEnabled: true, PasskeyCount: 0, BackupCodesRemaining: 10, SignedInDeviceCount: 1));

        Assert.Equal(SecurityCheckStatus.Recommended, Check(result, SecurityCheckKind.Passkey).Status);
        // 40 + 25 + 10 + 15 = 90 → still Strong: a passkey is a soft, phishing-resistance bonus.
        Assert.Equal(90, result.Score);
        Assert.Equal(SecurityGrade.Strong, result.Grade);
    }

    [Fact]
    public void A_lot_of_signed_in_devices_prompts_a_review()
    {
        var result = SecurityCheckupEvaluator.Evaluate(
            new SecurityPosture(TwoStepEnabled: true, PasskeyCount: 1, BackupCodesRemaining: 10, SignedInDeviceCount: 5));

        var devices = Check(result, SecurityCheckKind.SignedInDevices);
        Assert.Equal(SecurityCheckStatus.Recommended, devices.Status);
        Assert.Equal(RemediationArea.SignedInDevices, devices.Fix);
        Assert.Contains("5 devices", devices.Detail);
    }

    [Fact]
    public void A_single_device_passes_quietly()
    {
        var result = SecurityCheckupEvaluator.Evaluate(
            new SecurityPosture(TwoStepEnabled: true, PasskeyCount: 1, BackupCodesRemaining: 10, SignedInDeviceCount: 1));

        Assert.Equal(SecurityCheckStatus.Pass, Check(result, SecurityCheckKind.SignedInDevices).Status);
    }

    [Fact]
    public void A_middling_posture_grades_fair()
    {
        // Two-step off but a passkey present: 0 + 12.5 + 20 + 15 = 47.5 → 48 → Fair (≥45).
        var result = SecurityCheckupEvaluator.Evaluate(
            new SecurityPosture(TwoStepEnabled: false, PasskeyCount: 1, BackupCodesRemaining: 0, SignedInDeviceCount: 1));

        Assert.Equal(48, result.Score);
        Assert.Equal(SecurityGrade.Fair, result.Grade);
    }

    [Fact]
    public void Checks_are_ranked_most_urgent_first()
    {
        var result = SecurityCheckupEvaluator.Evaluate(
            new SecurityPosture(TwoStepEnabled: false, PasskeyCount: 0, BackupCodesRemaining: 0, SignedInDeviceCount: 1));

        // Action-needed (two-step) must lead; the passing device check must trail.
        Assert.Equal(SecurityCheckKind.TwoStepSignIn, result.Checks[0].Kind);
        Assert.Equal(SecurityCheckStatus.ActionNeeded, result.Checks[0].Status);
        Assert.Equal(SecurityCheckKind.SignedInDevices, result.Checks[^1].Kind);
        Assert.Equal(SecurityCheckStatus.Pass, result.Checks[^1].Status);
    }

    [Fact]
    public void Summary_counts_add_up_to_the_number_of_checks()
    {
        var result = SecurityCheckupEvaluator.Evaluate(
            new SecurityPosture(TwoStepEnabled: false, PasskeyCount: 0, BackupCodesRemaining: 0, SignedInDeviceCount: 1));

        Assert.Equal(1, result.ActionNeededCount);  // two-step
        Assert.Equal(2, result.RecommendedCount);    // backup codes + passkey
        Assert.Equal(1, result.PassCount);           // devices
        Assert.Equal(result.Checks.Count, result.ActionNeededCount + result.RecommendedCount + result.PassCount);
    }
}
