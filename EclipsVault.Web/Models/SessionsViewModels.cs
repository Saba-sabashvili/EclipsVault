using Microsoft.AspNetCore.Html;

namespace EclipsVault.Web.Models;

public sealed class SessionsViewModel
{
    /// <summary>The session the current request is on (null for a pre-feature cookie), so it can be marked.</summary>
    public Guid? CurrentSessionId { get; init; }

    public IReadOnlyList<ActiveSessionView> Sessions { get; init; } = [];

    public int OtherCount => Sessions.Count(s => !s.IsCurrent);
}

public sealed class ActiveSessionView
{
    public Guid SessionId { get; init; }
    public string Device { get; init; } = string.Empty;
    public string IpAddress { get; init; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; init; }
    public DateTimeOffset LastSeenAtUtc { get; init; }
    public bool IsCurrent { get; init; }
}

/// <summary>Presentation helpers for the signed-in-devices list: a device icon and relative time.</summary>
public static class SessionDisplay
{
    public static string Ago(DateTimeOffset timestamp, DateTimeOffset now) => AuditDisplay.Ago(timestamp, now);

    /// <summary>A device-class icon (phone / terminal / monitor) chosen from the device label.</summary>
    public static IHtmlContent Icon(string device)
    {
        var inner = Kind(device) switch
        {
            "phone" => "<rect x=\"7\" y=\"3\" width=\"10\" height=\"18\" rx=\"2\"/><path d=\"M11 18h2\"/>",
            "terminal" => "<rect x=\"3\" y=\"4\" width=\"18\" height=\"16\" rx=\"2\"/><path d=\"M7 9l3 3-3 3M13 15h4\"/>",
            _ => "<rect x=\"3\" y=\"4\" width=\"18\" height=\"12\" rx=\"2\"/><path d=\"M8 20h8M12 16v4\"/>"
        };

        return new HtmlString(
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" " +
            "stroke-linecap=\"round\" stroke-linejoin=\"round\">" + inner + "</svg>");
    }

    private static string Kind(string device)
    {
        if (device.Contains("iOS", StringComparison.OrdinalIgnoreCase) ||
            device.Contains("Android", StringComparison.OrdinalIgnoreCase))
        {
            return "phone";
        }
        if (device.Contains("curl", StringComparison.OrdinalIgnoreCase) ||
            device.Contains("python", StringComparison.OrdinalIgnoreCase) ||
            device.Contains("PowerShell", StringComparison.OrdinalIgnoreCase))
        {
            return "terminal";
        }
        return "monitor";
    }
}
