namespace EclipsVault.Core.Application.Sessions;

/// <summary>
/// Turns a raw User-Agent header into a short, human "device" label for the active-sessions
/// list — e.g. "Chrome on macOS", "Safari on iOS", "curl". Purely heuristic and best-effort:
/// User-Agent is attacker-controlled, so the label is for the owner's recognition only and is
/// never trusted for any decision. Pure and unit-tested.
/// </summary>
public static class UserAgentSummary
{
    public static string Describe(string? userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent))
        {
            return "Unknown device";
        }

        var browser = Browser(userAgent);
        var os = Os(userAgent);

        return (browser, os) switch
        {
            (not null, not null) => $"{browser} on {os}",
            (not null, null) => browser,
            (null, not null) => os,
            _ => "Unknown device"
        };
    }

    private static bool Has(string haystack, string needle)
        => haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);

    // Order matters: Edge/Opera masquerade as Chrome, and Chrome carries "Safari" in its UA.
    private static string? Browser(string ua) => ua switch
    {
        _ when Has(ua, "Edg") => "Edge",
        _ when Has(ua, "OPR") || Has(ua, "Opera") => "Opera",
        _ when Has(ua, "Firefox") => "Firefox",
        _ when Has(ua, "CriOS") || Has(ua, "Chrome") || Has(ua, "Chromium") => "Chrome",
        _ when Has(ua, "Safari") => "Safari",
        _ when Has(ua, "curl") => "curl",
        _ when Has(ua, "PowerShell") => "PowerShell",
        _ when Has(ua, "python") => "python",
        _ => null
    };

    private static string? Os(string ua) => ua switch
    {
        _ when Has(ua, "Windows") => "Windows",
        // iOS before macOS: iPhone/iPad UAs also contain "Mac OS X".
        _ when Has(ua, "iPhone") || Has(ua, "iPad") || Has(ua, "iPod") => "iOS",
        _ when Has(ua, "Android") => "Android",
        _ when Has(ua, "Mac OS X") || Has(ua, "Macintosh") => "macOS",
        _ when Has(ua, "CrOS") => "ChromeOS",
        _ when Has(ua, "Linux") => "Linux",
        _ => null
    };
}
