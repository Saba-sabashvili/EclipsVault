using EclipsVault.Core.Application.Abstractions;

namespace EclipsVault.Core.Application.Licensing;

public static class EvaluationWindowStoreExtensions
{
    /// <summary>
    /// Days left in a capability's evaluation period, or null if it has never been exercised and the
    /// period has therefore not started. Read-only: asking must never open the window, or simply
    /// opening the page would spend the operator's trial.
    /// </summary>
    public static async Task<int?> DaysRemainingAsync(
        this IEvaluationWindowStore windows, string featureKey, TimeProvider time, CancellationToken ct)
    {
        var startedAt = await windows.PeekAsync(featureKey, ct);
        return startedAt is null ? null : EvaluationWindow.DaysRemaining(startedAt.Value, time.GetUtcNow());
    }
}
