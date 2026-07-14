using EclipsVault.Core.Application.Activity;
using Microsoft.AspNetCore.Html;

namespace EclipsVault.Web.Models;

public sealed class ActivityIndexViewModel
{
    public required ActivityFeed Feed { get; init; }
}

/// <summary>Presentation mapping for the personal activity feed: category label, icon, and tone.</summary>
public static class ActivityDisplay
{
    public static string Label(ActivityCategory category) => category switch
    {
        ActivityCategory.Authentication => "Sign-in",
        ActivityCategory.Secrets => "Secrets",
        ActivityCategory.Sharing => "Sharing",
        ActivityCategory.Account => "Account",
        ActivityCategory.Security => "Security",
        ActivityCategory.Administration => "Admin",
        ActivityCategory.Automation => "Automation",
        _ => "Other"
    };

    /// <summary>Badge/accent tone, reusing the same tokens as the audit view (muted/warn/critical).</summary>
    public static string Tone(ActivitySeverity severity) => severity switch
    {
        ActivitySeverity.Critical => "critical",
        ActivitySeverity.Notable => "warn",
        _ => "muted"
    };

    /// <summary>Relative "time ago" — shares the audit view's formatter for a consistent feel.</summary>
    public static string Ago(DateTimeOffset timestamp, DateTimeOffset now) => AuditDisplay.Ago(timestamp, now);

    /// <summary>A small inline SVG per category, matching the sidebar's stroke-icon style.</summary>
    public static IHtmlContent Icon(ActivityCategory category)
    {
        var inner = category switch
        {
            ActivityCategory.Authentication => "<path d=\"M15 3h3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-3\"/><path d=\"M8 7l5 5-5 5M13 12H3\"/>",
            ActivityCategory.Secrets => "<rect x=\"4\" y=\"10\" width=\"16\" height=\"10\" rx=\"2\"/><path d=\"M8 10V7a4 4 0 0 1 8 0v3\"/><circle cx=\"12\" cy=\"15\" r=\"1.4\"/>",
            ActivityCategory.Sharing => "<circle cx=\"18\" cy=\"5\" r=\"2.6\"/><circle cx=\"6\" cy=\"12\" r=\"2.6\"/><circle cx=\"18\" cy=\"19\" r=\"2.6\"/><path d=\"M8.3 10.7l7.4-4.4M8.3 13.3l7.4 4.4\"/>",
            ActivityCategory.Account => "<circle cx=\"12\" cy=\"8\" r=\"3.4\"/><path d=\"M5 20c.7-3.7 3-5.5 7-5.5s6.3 1.8 7 5.5\"/>",
            ActivityCategory.Security => "<path d=\"M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z\"/><path d=\"M9 12l2 2 4-4\"/>",
            ActivityCategory.Administration => "<circle cx=\"12\" cy=\"12\" r=\"3\"/><path d=\"M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1\"/>",
            ActivityCategory.Automation => "<rect x=\"5\" y=\"7\" width=\"14\" height=\"12\" rx=\"2\"/><path d=\"M9 3v4M15 3v4M9 12h.01M15 12h.01M9 16h6\"/>",
            _ => "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 8h.01M11 12h1v4h1\"/>"
        };

        return new HtmlString(
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" " +
            "stroke-linecap=\"round\" stroke-linejoin=\"round\">" + inner + "</svg>");
    }
}
