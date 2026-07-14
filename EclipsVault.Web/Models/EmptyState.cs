namespace EclipsVault.Web.Models;

/// <summary>
/// A designed empty-state for a list page: an icon, a heading, an explanation of what the page
/// is for, and an optional call-to-action — so a page with no rows reads as "nothing here yet,
/// here's what it's for" instead of looking broken.
/// </summary>
public sealed class EmptyState
{
    /// <summary>Icon keyword resolved by <see cref="EmptyStateIcons"/> (falls back to a generic tray).</summary>
    public string Icon { get; init; } = "inbox";

    public required string Title { get; init; }

    public required string Message { get; init; }

    // Optional call-to-action rendered as a primary button when all three are set.
    public string? ActionText { get; init; }
    public string? ActionController { get; init; }
    public string? ActionAction { get; init; }

    public bool HasAction => ActionText is not null && ActionController is not null && ActionAction is not null;
}

/// <summary>Inline SVG icons for empty states, matching the sidebar's stroke style.</summary>
public static class EmptyStateIcons
{
    private const string Open = "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\" stroke-linecap=\"round\" stroke-linejoin=\"round\">";

    public static string Svg(string key) => Open + (key switch
    {
        "share" => "<circle cx=\"18\" cy=\"5\" r=\"2.6\"/><circle cx=\"6\" cy=\"12\" r=\"2.6\"/><circle cx=\"18\" cy=\"19\" r=\"2.6\"/><path d=\"M8.3 10.7l7.4-4.4M8.3 13.3l7.4 4.4\"/>",
        "mail" => "<rect x=\"3\" y=\"5\" width=\"18\" height=\"14\" rx=\"2\"/><path d=\"M4 7l8 6 8-6\"/>",
        "clipboard" => "<path d=\"M9 4h6a1 1 0 0 1 1 1v1h2a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h2V5a1 1 0 0 1 1-1Z\"/><path d=\"M9 14l2 2 4-4\"/>",
        "lock" => "<rect x=\"4\" y=\"10\" width=\"16\" height=\"10\" rx=\"2\"/><path d=\"M8 10V7a4 4 0 0 1 8 0v3\"/><circle cx=\"12\" cy=\"15\" r=\"1.4\"/>",
        "servers" => "<rect x=\"3\" y=\"4\" width=\"18\" height=\"6\" rx=\"1.5\"/><rect x=\"3\" y=\"14\" width=\"18\" height=\"6\" rx=\"1.5\"/><path d=\"M7 7h.01M7 17h.01\"/>",
        "network" => "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M3 12h18M12 3c2.7 2.6 4 5.7 4 9s-1.3 6.4-4 9c-2.7-2.6-4-5.7-4-9s1.3-6.4 4-9Z\"/>",
        _ => "<path d=\"M4 13h4l1.6 3h4.8L20 13h0\"/><path d=\"M5 13V6a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v7\"/><path d=\"M4 13v5a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-5\"/>"
    }) + "</svg>";
}
