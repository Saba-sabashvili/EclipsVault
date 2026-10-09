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

    /// <summary>
    /// When the window started at <paramref name="startedAtUtc"/> closes, saturating at
    /// <see cref="DateTimeOffset.MaxValue"/> rather than overflowing.
    ///
    /// <para>The clamp is not decoration. The start instant is read from a database row an operator
    /// can write, and <c>AddDays</c> throws on a start within 30 days of the end of time. Callers sit
    /// on the secret path — <c>PremiumFeatureUsageRecorder</c> asks <see cref="IsActive"/> outside the
    /// try/catch that guards the store lookup — so an exception here would break the rule that
    /// licensing never throws into a vault operation, turning a licence question into a 500 on issuing
    /// a credential. Saturating answers the question instead: a window that far out has not closed.</para>
    /// </summary>
    public static DateTimeOffset EndsAt(DateTimeOffset startedAtUtc)
    {
        // Compare and add in the same time basis. AddDays preserves the source offset, whose
        // local date can overflow even when its UTC instant is below the saturation boundary.
        var start = startedAtUtc.ToUniversalTime();
        return start > DateTimeOffset.MaxValue.AddDays(-Days)
            ? DateTimeOffset.MaxValue
            : start.AddDays(Days);
    }

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
