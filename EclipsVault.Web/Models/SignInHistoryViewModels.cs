using EclipsVault.Core.Application.SignInHistory;
using Microsoft.AspNetCore.Html;

namespace EclipsVault.Web.Models;

public sealed class SignInHistoryViewModel
{
    public required SignInHistory History { get; init; }
}

/// <summary>Presentation mapping for the sign-in history timeline: labels, tones, and icons.</summary>
public static class SignInDisplay
{
    public static string OutcomeLabel(SignInOutcome outcome) => outcome switch
    {
        SignInOutcome.Success => "Success",
        SignInOutcome.Failed => "Failed",
        SignInOutcome.Blocked => "Blocked",
        _ => "Info"
    };

    /// <summary>Badge tone reusing the shared tokens (ok/warn/danger/muted).</summary>
    public static string OutcomeTone(SignInOutcome outcome) => outcome switch
    {
        SignInOutcome.Success => "ok",
        SignInOutcome.Failed => "warn",
        SignInOutcome.Blocked => "danger",
        _ => "muted"
    };

    /// <summary>Feed-item severity class, matching the activity feed's icon styling.</summary>
    public static string FeedSeverity(SignInOutcome outcome) => outcome switch
    {
        SignInOutcome.Blocked => "sev-critical",
        SignInOutcome.Failed => "sev-warn",
        _ => ""
    };

    public static string MethodLabel(SignInMethod method) => method switch
    {
        SignInMethod.Password => "Password + 2FA",
        SignInMethod.TwoFactor => "Two-factor",
        SignInMethod.Passkey => "Passkey",
        SignInMethod.RecoveryCode => "Recovery code",
        SignInMethod.StepUp => "Step-up",
        _ => "System"
    };

    /// <summary>The location badge text + tone, or null when there is nothing worth flagging.</summary>
    public static (string Text, string Tone)? LocationBadge(SignInLocationFlag flag) => flag switch
    {
        SignInLocationFlag.FirstSeen => ("New location", "muted"),
        SignInLocationFlag.Unfamiliar => ("Unfamiliar location", "danger"),
        _ => null
    };

    /// <summary>Relative "time ago" — shares the audit view's formatter for a consistent feel.</summary>
    public static string Ago(DateTimeOffset timestamp, DateTimeOffset now) => AuditDisplay.Ago(timestamp, now);

    /// <summary>Absolute UTC label for the tooltip.</summary>
    public static string Absolute(DateTimeOffset timestamp) =>
        timestamp.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");

    /// <summary>A small inline SVG per method, matching the sidebar's stroke-icon style.</summary>
    public static IHtmlContent Icon(SignInMethod method)
    {
        var inner = method switch
        {
            SignInMethod.Passkey => "<rect x=\"3\" y=\"11\" width=\"18\" height=\"10\" rx=\"2\"/><path d=\"M7 11V8a5 5 0 0 1 9-3\"/><circle cx=\"12\" cy=\"16\" r=\"1.4\"/>",
            SignInMethod.RecoveryCode => "<rect x=\"3\" y=\"5\" width=\"18\" height=\"14\" rx=\"2\"/><path d=\"M7 9h4M7 13h6M15 9h2\"/>",
            SignInMethod.StepUp => "<path d=\"M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z\"/><path d=\"M12 8v4M12 15h.01\"/>",
            SignInMethod.TwoFactor => "<rect x=\"6\" y=\"10\" width=\"12\" height=\"9\" rx=\"1.6\"/><path d=\"M9 10V7.5a3 3 0 0 1 6 0V10\"/>",
            SignInMethod.System => "<circle cx=\"12\" cy=\"12\" r=\"3\"/><path d=\"M12 4v2M12 18v2M4 12h2M18 12h2M6.3 6.3l1.4 1.4M16.3 16.3l1.4 1.4M17.7 6.3l-1.4 1.4M7.7 16.3l-1.4 1.4\"/>",
            _ => "<path d=\"M15 3h3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-3\"/><path d=\"M8 7l5 5-5 5M13 12H3\"/>"
        };

        return new HtmlString(
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" " +
            "stroke-linecap=\"round\" stroke-linejoin=\"round\">" + inner + "</svg>");
    }
}
