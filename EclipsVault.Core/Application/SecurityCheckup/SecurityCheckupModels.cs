namespace EclipsVault.Core.Application.SecurityCheckup;

/// <summary>
/// A point-in-time snapshot of the signed-in user's own security posture. Pure inputs — every
/// field is gathered from an existing service — so the scoring can be a deterministic function
/// with no I/O. See <see cref="SecurityCheckupEvaluator"/>.
/// </summary>
public sealed record SecurityPosture(
    bool TwoStepEnabled,
    int PasskeyCount,
    int BackupCodesRemaining,
    int SignedInDeviceCount);

/// <summary>The result of one control: its standing plus plain-language guidance and where to act.</summary>
public sealed record SecurityCheck(
    SecurityCheckKind Kind,
    SecurityCheckStatus Status,
    string Title,
    string Detail,
    string Recommendation,
    RemediationArea Fix);

/// <summary>
/// The whole checkup: every control's result, a 0–100 score, and the grade it rolls up to. The
/// checks are pre-sorted most-important-first, so the first is always the thing worth doing next.
/// </summary>
public sealed record SecurityCheckup(IReadOnlyList<SecurityCheck> Checks, int Score, SecurityGrade Grade)
{
    public int ActionNeededCount => Checks.Count(c => c.Status == SecurityCheckStatus.ActionNeeded);

    public int RecommendedCount => Checks.Count(c => c.Status == SecurityCheckStatus.Recommended);

    public int PassCount => Checks.Count(c => c.Status == SecurityCheckStatus.Pass);

    /// <summary>The single most important thing to do next, or null when everything passes.</summary>
    public SecurityCheck? TopPriority =>
        Checks.FirstOrDefault(c => c.Status != SecurityCheckStatus.Pass);

    public bool AllClear => TopPriority is null;
}
