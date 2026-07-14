namespace EclipsVault.Core.Application.Activity;

/// <summary>Broad grouping a personal-activity entry falls under, for filtering and iconography.</summary>
public enum ActivityCategory
{
    Authentication,
    Secrets,
    Sharing,
    Account,
    Security,
    Administration,
    Automation,
    Other
}

/// <summary>How much attention an entry warrants when a user scans their own history.</summary>
public enum ActivitySeverity
{
    Routine,
    Notable,
    Critical
}

/// <summary>The pure, presentation-independent classification of a single audit action.</summary>
public sealed record ActivityDescription(ActivityCategory Category, string Title, ActivitySeverity Severity);

/// <summary>One entry in a user's personal activity feed.</summary>
public sealed record ActivityItem(
    DateTimeOffset TimestampUtc,
    ActivityCategory Category,
    string Title,
    ActivitySeverity Severity,
    string? ResourceName,
    string SourceIp);

/// <summary>A page of a user's activity feed, newest first.</summary>
public sealed record ActivityFeed(
    IReadOnlyList<ActivityItem> Items,
    int Page,
    int PageSize,
    bool HasMore)
{
    /// <summary>True when there is an earlier (more recent) page to step back to.</summary>
    public bool HasPrevious => Page > 1;

    /// <summary>Count of notable-or-worse entries on this page — a quick "worth a look" signal.</summary>
    public int NotableCount => Items.Count(i => i.Severity != ActivitySeverity.Routine);

    public static ActivityFeed Empty(int pageSize) => new([], 1, pageSize, false);
}
