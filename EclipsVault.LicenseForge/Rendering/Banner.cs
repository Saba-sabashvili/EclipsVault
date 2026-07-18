using System.Text;

namespace EclipsVault.LicenseForge.Rendering;

/// <summary>
/// The tool header: the eclipse glyph and an <c>ECLIPSVAULT</c> wordmark painted along the corona
/// gradient, a matching gradient rule, and a subtitle. A framed gradient wordmark (rather than a wide
/// figlet) stays legible on narrow terminals and never misaligns.
/// </summary>
public static class Banner
{
    public static void Print()
    {
        const string word = "ECLIPSVAULT";

        Console.WriteLine();

        var sb = new StringBuilder("  ");
        sb.Append(Theme.Fg(Theme.Accent)).Append("🌒").Append(Theme.Reset).Append("  ");
        for (var i = 0; i < word.Length; i++)
        {
            var t = word.Length == 1 ? 0d : (double)i / (word.Length - 1);
            sb.Append(Theme.Fg(Theme.Sample(t))).Append(Theme.Bold).Append(word[i]).Append(Theme.Reset);
            if (i < word.Length - 1) sb.Append(' ');
        }
        Console.WriteLine(sb.ToString());

        Render.GradientRule(28);
        Console.WriteLine(
            $"  {Theme.Fg(Theme.Muted)}License Forge{Theme.Reset}  {Theme.Fg(Theme.Subtle)}·{Theme.Reset}  " +
            $"{Theme.Fg(Theme.Muted)}offline license minting for a self-hosted vault{Theme.Reset}");
        Console.WriteLine();
    }
}
