namespace EclipsVault.Core.Application.SignInHistory;

/// <summary>The pure, presentation-independent classification of one sign-in audit action.</summary>
public sealed record SignInDescriptor(SignInOutcome Outcome, SignInMethod Method, string Title);

/// <summary>One entry in the user's sign-in history, newest first when listed.</summary>
public sealed record SignInEvent(
    DateTimeOffset TimestampUtc,
    SignInOutcome Outcome,
    SignInMethod Method,
    string Title,
    string SourceIp,
    SignInLocationFlag LocationFlag);

/// <summary>A rollup of the recent sign-in events, for the "at a glance" header.</summary>
public sealed record SignInSummary(
    int SuccessCount,
    int FailedCount,
    int SuspiciousCount,
    int DistinctLocations,
    DateTimeOffset? LastSuccessUtc,
    DateTimeOffset? LastFailedUtc)
{
    /// <summary>
    /// True when there is at least one failed/blocked attempt from a location the user has never
    /// signed in from — the case worth a second look. Ordinary failures (a fat-fingered password
    /// from your own device) don't raise this on their own.
    /// </summary>
    public bool NeedsAttention => SuspiciousCount > 0;

    public static SignInSummary Empty => new(0, 0, 0, 0, null, null);
}

/// <summary>The user's recent sign-in history: the event timeline plus its summary.</summary>
public sealed record SignInHistory(IReadOnlyList<SignInEvent> Events, SignInSummary Summary)
{
    public bool IsEmpty => Events.Count == 0;

    public static SignInHistory Empty => new([], SignInSummary.Empty);
}
