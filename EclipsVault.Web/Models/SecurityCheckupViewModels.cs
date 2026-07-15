using EclipsVault.Core.Application.SecurityCheckup;
using Microsoft.AspNetCore.Html;

namespace EclipsVault.Web.Models;

public sealed class SecurityCheckupViewModel
{
    public required SecurityCheckup Checkup { get; init; }
}

/// <summary>
/// Presentation mapping for the security checkup: status tones, per-control icons, the score-ring
/// geometry, and the translation of a Core <see cref="RemediationArea"/> into a concrete route. All
/// SVG uses presentation attributes (never a <c>style=</c> attribute), so it stays within the strict,
/// no-inline-styles CSP.
/// </summary>
public static class SecurityCheckupDisplay
{
    // Score-ring geometry (an SVG donut). The value arc is drawn with stroke-dasharray, which is a
    // presentation attribute — CSP-clean — so the fill can be computed server-side per score.
    public const double RingRadius = 52;
    public const double RingCircumference = 2 * Math.PI * RingRadius;

    /// <summary>Length of the filled arc for a 0–100 score.</summary>
    public static double ArcLength(int score) => RingCircumference * Math.Clamp(score, 0, 100) / 100.0;

    /// <summary>Badge tone token (ok/warn/danger) for a control's standing.</summary>
    public static string StatusTone(SecurityCheckStatus status) => status switch
    {
        SecurityCheckStatus.Pass => "ok",
        SecurityCheckStatus.Recommended => "warn",
        _ => "danger"
    };

    /// <summary>Modifier class placed on the feed row, colouring the control's icon chip.</summary>
    public static string StatusClass(SecurityCheckStatus status) => status switch
    {
        SecurityCheckStatus.Pass => "check-pass",
        SecurityCheckStatus.Recommended => "check-warn",
        _ => "check-fail"
    };

    public static string StatusLabel(SecurityCheckStatus status) => status switch
    {
        SecurityCheckStatus.Pass => "Secured",
        SecurityCheckStatus.Recommended => "Recommended",
        _ => "Action needed"
    };

    public static string GradeLabel(SecurityGrade grade) => grade switch
    {
        SecurityGrade.Strong => "Strong",
        SecurityGrade.Good => "Good",
        SecurityGrade.Fair => "Fair",
        _ => "At risk"
    };

    /// <summary>Ring/headline colour class, keyed to the grade.</summary>
    public static string GradeClass(SecurityGrade grade) => grade switch
    {
        SecurityGrade.Strong => "grade-strong",
        SecurityGrade.Good => "grade-good",
        SecurityGrade.Fair => "grade-fair",
        _ => "grade-atrisk"
    };

    /// <summary>Where the "fix it" button goes, or null when the control has nothing to act on.</summary>
    public static (string Controller, string Action)? FixRoute(RemediationArea area) => area switch
    {
        // Backup codes are generated from the profile page, so both land there.
        RemediationArea.Profile => ("Profile", "Index"),
        RemediationArea.BackupCodes => ("Profile", "Index"),
        RemediationArea.SignedInDevices => ("Sessions", "Index"),
        _ => null
    };

    /// <summary>Call-to-action label, phrased per control so the button reads like the next step.</summary>
    public static string CtaLabel(SecurityCheckKind kind) => kind switch
    {
        SecurityCheckKind.TwoStepSignIn => "Set up two-step",
        SecurityCheckKind.BackupCodes => "Generate codes",
        SecurityCheckKind.Passkey => "Add a passkey",
        SecurityCheckKind.SignedInDevices => "Review devices",
        _ => "Open settings"
    };

    /// <summary>A small inline SVG per control, matching the sidebar's stroke-icon style.</summary>
    public static IHtmlContent Icon(SecurityCheckKind kind)
    {
        var inner = kind switch
        {
            SecurityCheckKind.TwoStepSignIn => "<path d=\"M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z\"/><path d=\"M9 12l2 2 4-4\"/>",
            SecurityCheckKind.BackupCodes => "<rect x=\"4\" y=\"4\" width=\"16\" height=\"16\" rx=\"2\"/><path d=\"M8 9h8M8 13h5M8 17h3\"/>",
            SecurityCheckKind.Passkey => "<circle cx=\"8\" cy=\"15\" r=\"4\"/><path d=\"M10.85 12.15 19 4M18 5l2 2M15 8l2 2\"/>",
            SecurityCheckKind.SignedInDevices => "<rect x=\"2\" y=\"4\" width=\"14\" height=\"10\" rx=\"1.6\"/><path d=\"M6 18h6M9 14v4\"/><rect x=\"17\" y=\"9\" width=\"5\" height=\"11\" rx=\"1.4\"/>",
            _ => "<circle cx=\"12\" cy=\"12\" r=\"9\"/>"
        };

        return new HtmlString(
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" " +
            "stroke-linecap=\"round\" stroke-linejoin=\"round\">" + inner + "</svg>");
    }
}
