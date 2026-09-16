using EclipsVault.Core.Application.Licensing;
using Xunit;

namespace EclipsVault.Tests.Licensing;

/// <summary>
/// The evaluation period is a promise made in the licence, so the arithmetic behind it is pinned
/// here rather than only through the gate that consumes it.
/// </summary>
public class EvaluationWindowTests
{
    private static readonly DateTimeOffset Start = new(2026, 9, 7, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void The_period_matches_the_licence()
        => Assert.Equal(30, EvaluationWindow.Days);

    [Fact]
    public void It_ends_thirty_days_after_it_opened()
        => Assert.Equal(Start.AddDays(30), EvaluationWindow.EndsAt(Start));

    [Fact]
    public void It_is_active_on_the_day_it_opens()
        => Assert.True(EvaluationWindow.IsActive(Start, Start));

    [Fact]
    public void It_is_active_one_second_before_it_closes()
        => Assert.True(EvaluationWindow.IsActive(Start, Start.AddDays(30).AddSeconds(-1)));

    /// <summary>"Up to 30 consecutive days" is read in the operator's favour at the boundary.</summary>
    [Fact]
    public void It_is_still_active_at_the_closing_instant()
        => Assert.True(EvaluationWindow.IsActive(Start, Start.AddDays(30)));

    [Fact]
    public void It_is_spent_one_second_after_it_closes()
        => Assert.False(EvaluationWindow.IsActive(Start, Start.AddDays(30).AddSeconds(1)));

    [Fact]
    public void A_fresh_window_has_all_its_days()
        => Assert.Equal(30, EvaluationWindow.DaysRemaining(Start, Start));

    /// <summary>Rounded up, so a window with hours left never reads "0 days" while it still works.</summary>
    [Fact]
    public void A_partial_day_still_counts_as_a_day()
        => Assert.Equal(1, EvaluationWindow.DaysRemaining(Start, Start.AddDays(29).AddHours(12)));

    [Fact]
    public void A_spent_window_reports_no_days_rather_than_a_negative_number()
        => Assert.Equal(0, EvaluationWindow.DaysRemaining(Start, Start.AddDays(45)));

    [Fact]
    public void A_start_near_the_end_of_time_does_not_throw_out_of_the_licensing_path()
    {
        // Licensing must never throw into a secret operation: PremiumFeatureUsageRecorder calls
        // IsActive OUTSIDE the try/catch that guards the store lookup, so an AddDays overflow here
        // would surface as a 500 on issuing a dynamic secret rather than as a clean licence answer.
        // A stored start can be anything an operator wrote into the row.
        var absurd = DateTimeOffset.MaxValue.AddDays(-1);

        var ends = EvaluationWindow.EndsAt(absurd);
        var active = EvaluationWindow.IsActive(absurd, DateTimeOffset.UnixEpoch);
        var remaining = EvaluationWindow.DaysRemaining(absurd, DateTimeOffset.UnixEpoch);

        Assert.Equal(DateTimeOffset.MaxValue, ends);
        Assert.True(active);
        Assert.True(remaining > 0);
    }
}
