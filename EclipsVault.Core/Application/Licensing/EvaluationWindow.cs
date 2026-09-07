namespace EclipsVault.Core.Application.Licensing;

/// <summary>
/// The evaluation period the licence grants for a Licensed Capability: 30 consecutive days of
/// production use from first use, without a licence key. Pure and side-effect-free so the policy can
/// be reasoned about and tested on its own; where a window started is the store's problem.
/// </summary>
public static class EvaluationWindow
{
    /// <summary>
    /// Days granted. Must stay equal to the period in LICENSE section 2 — if one changes, both change.
    /// </summary>
    public const int Days = 30;

    /// <summary>When the window started at <paramref name="startedAtUtc"/> closes.</summary>
    public static DateTimeOffset EndsAt(DateTimeOffset startedAtUtc) => startedAtUtc.AddDays(Days);

    /// <summary>
    /// True while the capability may still be used unlicensed. The boundary is inclusive of the
    /// final instant: "up to 30 consecutive days" is read in the operator's favour.
    /// </summary>
    public static bool IsActive(DateTimeOffset startedAtUtc, DateTimeOffset nowUtc)
        => nowUtc <= EndsAt(startedAtUtc);

    /// <summary>
    /// Whole days left, rounded up so a window with any time left never reads "0 days", and floored
    /// at zero. For display only.
    /// </summary>
    public static int DaysRemaining(DateTimeOffset startedAtUtc, DateTimeOffset nowUtc)
    {
        var left = EndsAt(startedAtUtc) - nowUtc;
        return left <= TimeSpan.Zero ? 0 : (int)Math.Ceiling(left.TotalDays);
    }
}
