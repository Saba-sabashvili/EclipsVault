namespace EclipsVault.Core.Application.SecurityCheckup;

/// <summary>
/// Turns a <see cref="SecurityPosture"/> snapshot into a scored, ranked <see cref="SecurityCheckup"/>.
/// Pure and deterministic — no I/O, no clock — so the whole scoring model is exercisable in a unit
/// test. Each control carries a weight; its contribution is the weight times a factor (pass = 1,
/// recommended = ½, action-needed = 0), and the score is the weighted percentage. Weights sum to 100
/// so the score reads directly as "how much of your posture is in place".
/// </summary>
public static class SecurityCheckupEvaluator
{
    // The relative importance of each control. Two-step sign-in is the single biggest lever, so it
    // carries the most weight; the device count is an awareness nudge, so it carries the least.
    private const int TwoStepWeight = 40;
    private const int BackupCodesWeight = 25;
    private const int PasskeyWeight = 20;
    private const int DevicesWeight = 15;

    /// <summary>At or above this many active devices, we nudge the user to review the list.</summary>
    private const int BusyDeviceThreshold = 4;

    /// <summary>A "running low" threshold for backup codes — a full set is ten.</summary>
    private const int LowBackupCodes = 2;

    public static SecurityCheckup Evaluate(SecurityPosture posture)
    {
        var twoStep = EvaluateTwoStep(posture);
        var backupCodes = EvaluateBackupCodes(posture);
        var passkey = EvaluatePasskey(posture);
        var devices = EvaluateDevices(posture);

        var weighted =
            TwoStepWeight * Factor(twoStep.Status) +
            BackupCodesWeight * Factor(backupCodes.Status) +
            PasskeyWeight * Factor(passkey.Status) +
            DevicesWeight * Factor(devices.Status);

        // Weights already sum to 100, so the weighted total is the percentage.
        var score = (int)Math.Round(weighted, MidpointRounding.AwayFromZero);

        // Rank the list so the most urgent control is first (action-needed above recommended above
        // pass); ties keep their declared order via a stable sort.
        var checks = new[] { twoStep, backupCodes, passkey, devices }
            .OrderByDescending(c => (int)c.Status)
            .ToList();

        return new SecurityCheckup(checks, score, GradeFor(score));
    }

    private static double Factor(SecurityCheckStatus status) => status switch
    {
        SecurityCheckStatus.Pass => 1.0,
        SecurityCheckStatus.Recommended => 0.5,
        _ => 0.0
    };

    private static SecurityGrade GradeFor(int score) => score switch
    {
        >= 90 => SecurityGrade.Strong,
        >= 70 => SecurityGrade.Good,
        >= 45 => SecurityGrade.Fair,
        _ => SecurityGrade.AtRisk
    };

    private static SecurityCheck EvaluateTwoStep(SecurityPosture p) => p.TwoStepEnabled
        ? new SecurityCheck(SecurityCheckKind.TwoStepSignIn, SecurityCheckStatus.Pass,
            "Two-step sign-in", "An authenticator app is protecting your sign-in.",
            "You're all set. Keep your authenticator app backed up.", RemediationArea.None)
        : new SecurityCheck(SecurityCheckKind.TwoStepSignIn, SecurityCheckStatus.ActionNeeded,
            "Two-step sign-in", "Your account relies on a password alone.",
            "Turn on an authenticator app so a stolen password isn't enough to get in.", RemediationArea.Profile);

    private static SecurityCheck EvaluateBackupCodes(SecurityPosture p)
    {
        // Backup codes only do anything once two-step is on; until then the real fix is two-step,
        // so we hold this at a gentle "recommended" rather than piling on a second red mark.
        if (!p.TwoStepEnabled)
        {
            return new SecurityCheck(SecurityCheckKind.BackupCodes, SecurityCheckStatus.Recommended,
                "Backup codes", "Backup codes become available once two-step sign-in is on.",
                "Turn on two-step sign-in, then generate a set of one-time backup codes.", RemediationArea.Profile);
        }

        if (p.BackupCodesRemaining <= 0)
        {
            return new SecurityCheck(SecurityCheckKind.BackupCodes, SecurityCheckStatus.ActionNeeded,
                "Backup codes", "You have no backup codes left.",
                "Generate a fresh set so you can get in if you ever lose your authenticator.", RemediationArea.BackupCodes);
        }

        if (p.BackupCodesRemaining <= LowBackupCodes)
        {
            return new SecurityCheck(SecurityCheckKind.BackupCodes, SecurityCheckStatus.Recommended,
                "Backup codes", $"Only {p.BackupCodesRemaining} backup code{(p.BackupCodesRemaining == 1 ? "" : "s")} left.",
                "Generate a fresh set before you run out.", RemediationArea.BackupCodes);
        }

        return new SecurityCheck(SecurityCheckKind.BackupCodes, SecurityCheckStatus.Pass,
            "Backup codes", $"You have {p.BackupCodesRemaining} one-time backup codes.",
            "Keep them somewhere safe and offline.", RemediationArea.None);
    }

    private static SecurityCheck EvaluatePasskey(SecurityPosture p) => p.PasskeyCount > 0
        ? new SecurityCheck(SecurityCheckKind.Passkey, SecurityCheckStatus.Pass,
            "Passkey", $"You have {p.PasskeyCount} passkey{(p.PasskeyCount == 1 ? "" : "s")} for phishing-resistant sign-in.",
            "Great — passkeys can't be phished or replayed.", RemediationArea.None)
        : new SecurityCheck(SecurityCheckKind.Passkey, SecurityCheckStatus.Recommended,
            "Passkey", "You haven't added a passkey yet.",
            "Add a passkey for sign-in that can't be phished, even if your password leaks.", RemediationArea.Profile);

    private static SecurityCheck EvaluateDevices(SecurityPosture p) => p.SignedInDeviceCount >= BusyDeviceThreshold
        ? new SecurityCheck(SecurityCheckKind.SignedInDevices, SecurityCheckStatus.Recommended,
            "Signed-in devices", $"{p.SignedInDeviceCount} devices are signed in to your account.",
            "Review the list and sign out anything you don't recognise.", RemediationArea.SignedInDevices)
        : new SecurityCheck(SecurityCheckKind.SignedInDevices, SecurityCheckStatus.Pass,
            "Signed-in devices",
            p.SignedInDeviceCount <= 1
                ? "Only this device is signed in."
                : $"{p.SignedInDeviceCount} devices are signed in — all accounted for.",
            "Check this list whenever you sign in somewhere new.", RemediationArea.SignedInDevices);
}
