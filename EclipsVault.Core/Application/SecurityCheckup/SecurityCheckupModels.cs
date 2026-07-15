namespace EclipsVault.Core.Application.SecurityCheckup;

/// <summary>
/// How a single control scored. Ordered by urgency so a numeric compare (used to rank the
/// list most-important-first) puts problems above passes.
/// </summary>
public enum SecurityCheckStatus
{
    /// <summary>The control is in place — nothing to do.</summary>
    Pass = 0,

    /// <summary>Not wrong, but the account would be stronger with it addressed.</summary>
    Recommended = 1,

    /// <summary>A real gap that meaningfully weakens the account — do this first.</summary>
    ActionNeeded = 2
}

/// <summary>Stable identity of each control, so views/tests can refer to one without matching on prose.</summary>
public enum SecurityCheckKind
{
    TwoStepSignIn,
    BackupCodes,
    Passkey,
    SignedInDevices
}

/// <summary>
/// Where a control is fixed, named in the domain's own terms. The Web layer maps this to a
/// concrete route — Core stays free of any MVC/URL concern.
/// </summary>
public enum RemediationArea
{
    None,
    Profile,
    BackupCodes,
    SignedInDevices
}

/// <summary>The overall standing derived from the score, for a one-word headline.</summary>
public enum SecurityGrade
{
    AtRisk,
    Fair,
    Good,
    Strong
}

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
