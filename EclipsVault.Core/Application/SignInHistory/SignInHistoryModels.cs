namespace EclipsVault.Core.Application.SignInHistory;

/// <summary>How a single sign-in-related event turned out.</summary>
public enum SignInOutcome
{
    /// <summary>Authentication succeeded (password+MFA, passkey, recovery code, or a passed step-up).</summary>
    Success,

    /// <summary>An authentication attempt was rejected (wrong password, bad code, failed step-up).</summary>
    Failed,

    /// <summary>The account was locked after repeated failures — access was blocked, not merely refused.</summary>
    Blocked,

    /// <summary>An informational state change (e.g. the account was unlocked). No credential was presented.</summary>
    Info
}

/// <summary>Which credential the attempt used, so the timeline reads clearly.</summary>
public enum SignInMethod
{
    Password,
    TwoFactor,
    Passkey,
    RecoveryCode,
    StepUp,
    System
}

/// <summary>
/// A location signal derived purely from the event stream — never an external geo lookup.
/// It says only whether an IP is one you have signed in from before, within the recent history.
/// </summary>
public enum SignInLocationFlag
{
    /// <summary>Nothing notable — a known location, or an informational event.</summary>
    None,

    /// <summary>The first successful sign-in from this IP in the recent history ("you've not signed in from here before").</summary>
    FirstSeen,

    /// <summary>A failed or blocked attempt from an IP you have never successfully signed in from — the strongest "was this you?" signal.</summary>
    Unfamiliar
}

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
