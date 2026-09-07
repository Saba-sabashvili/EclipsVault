namespace EclipsVault.Core.Application.Abstractions;

/// <summary>The start of a capability's evaluation window, and whether this call opened it.</summary>
public readonly record struct EvaluationStart(DateTimeOffset StartedAtUtc, bool StartedNow);

/// <summary>
/// Remembers when each Licensed Capability was first exercised, which is what starts the evaluation
/// period granted by the licence. Two operations deliberately, because the distinction is the point:
/// <see cref="PeekAsync"/> reads without starting anything (the UI must be able to say "not
/// licensed" without silently consuming the trial), while <see cref="GetOrStartAsync"/> opens the
/// window on first use.
/// </summary>
public interface IEvaluationWindowStore
{
    /// <summary>The window start for <paramref name="featureKey"/>, or null if it has never been
    /// exercised. Read-only — never opens a window.</summary>
    Task<DateTimeOffset?> PeekAsync(string featureKey, CancellationToken ct);

    /// <summary>
    /// The window start for <paramref name="featureKey"/>, opening it at the current instant if this
    /// is the first use. Concurrency-safe: when two nodes race, both observe the winner's start.
    /// </summary>
    Task<EvaluationStart> GetOrStartAsync(string featureKey, CancellationToken ct);
}
