using System.Security.Cryptography;
using System.Text;

namespace EclipsVault.Web.Services;

/// <summary>
/// Deterministic fallback avatar: initials on a hashed colour. Rendered as a small,
/// script-free SVG so it can be served as an image without an upload attack surface.
/// </summary>
public static class Identicon
{
    public static string InitialsFrom(string name)
    {
        var parts = name.Split([' ', '-', '.', '_'], StringSplitOptions.RemoveEmptyEntries);
        return parts.Length switch
        {
            0 => "?",
            1 => parts[0][..1].ToUpperInvariant(),
            _ => (parts[0][..1] + parts[^1][..1]).ToUpperInvariant()
        };
    }

    public static string Svg(string seed)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(seed));
        var hue = hash[0] * 360 / 256;
        var initials = System.Net.WebUtility.HtmlEncode(InitialsFrom(seed));

        var bg = $"hsl({hue} 58% 42%)";
        var bgDeep = $"hsl({(hue + 24) % 360} 60% 30%)";

        return $"""
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128" role="img" aria-label="Avatar">
              <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0" stop-color="{bg}"/><stop offset="1" stop-color="{bgDeep}"/>
              </linearGradient></defs>
              <rect width="128" height="128" rx="24" fill="url(#g)"/>
              <text x="50%" y="50%" dy="0.35em" text-anchor="middle"
                    font-family="-apple-system, Segoe UI, Roboto, sans-serif" font-size="56"
                    font-weight="600" fill="#fff">{initials}</text>
            </svg>
            """;
    }
}
