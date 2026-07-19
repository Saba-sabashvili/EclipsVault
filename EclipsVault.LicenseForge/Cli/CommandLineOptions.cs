namespace EclipsVault.LicenseForge.Cli;

/// <summary>
/// A tiny <c>--flag value</c> parser for the mint verb. Reads space-separated pairs
/// (<c>--tier Pro --nodes 3</c>) into a case-sensitive map and exposes typed lookups, so the command
/// itself stays free of parsing noise. A flag with no following token is ignored; if a flag repeats,
/// the last value wins.
/// </summary>
public sealed class CommandLineOptions
{
    private readonly Dictionary<string, string> _values;

    private CommandLineOptions(Dictionary<string, string> values) => _values = values;

    /// <summary>Parse <paramref name="args"/> from <paramref name="start"/> onward (skipping the verb).</summary>
    public static CommandLineOptions Parse(string[] args, int start = 1)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = start; i < args.Length - 1; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal))
                continue;
            values[args[i][2..]] = args[i + 1];
            i++;
        }
        return new CommandLineOptions(values);
    }

    /// <summary>The raw value for <paramref name="name"/>, or <c>null</c> if the flag was not supplied.</summary>
    public string? Get(string name) => _values.TryGetValue(name, out var value) ? value : null;

    /// <summary>The value parsed as an int, or <paramref name="fallback"/> if absent or unparseable.</summary>
    public int GetInt(string name, int fallback = 0)
        => int.TryParse(Get(name), out var parsed) ? parsed : fallback;
}
