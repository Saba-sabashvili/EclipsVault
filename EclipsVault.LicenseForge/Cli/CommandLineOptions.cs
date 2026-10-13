using System.Globalization;

namespace EclipsVault.LicenseForge.Cli;

/// <summary>
/// A tiny flag parser for the forge verbs. Accepts both <c>--flag value</c> and <c>--flag=value</c>,
/// and refuses everything else: a flag whose value is missing, a flag outside the verb's known set,
/// a value that is not a whole number, a negative number, and a bare word with no flag in front of it.
///
/// <para><b>Why it fails closed.</b> A licence cannot be revoked once it reaches a customer —
/// verification is offline, with no phone-home — so a mis-mint is permanent. This parser used to drop
/// a malformed flag silently, and every consumer then fell back to a default: no expiry, unlimited
/// nodes. That made the *most generous licence we can issue* the result of a typo. Refusing is the
/// only safe direction, because the operator can always retype the command, and cannot ever recall a
/// token. If a flag repeats, the last value wins.</para>
/// </summary>
public sealed class CommandLineOptions
{
    private readonly Dictionary<string, string> _values;

    private CommandLineOptions(Dictionary<string, string> values) => _values = values;

    /// <summary>Either the parsed options or a human-readable reason the command line was refused.</summary>
    public readonly record struct ParseResult(CommandLineOptions? Options, string? Error)
    {
        public bool Ok => Error is null;
        internal static ParseResult Success(CommandLineOptions options) => new(options, null);
        internal static ParseResult Failure(string error) => new(null, error);
    }

    /// <summary>
    /// A numeric flag lookup. An absent flag is <em>success with a null value</em> so the caller can
    /// apply its own default; only a value that is present and unusable is an error. Distinguishing
    /// those two is the whole point — conflating them is what minted perpetual licences.
    /// </summary>
    public readonly record struct IntResult(int? Value, string? Error)
    {
        public bool Ok => Error is null;
        internal static IntResult Success(int? value) => new(value, null);
        internal static IntResult Failure(string error) => new(null, error);
    }

    /// <summary>Parse <paramref name="args"/> from <paramref name="start"/> onward (skipping the verb).</summary>
    public static ParseResult Parse(string[] args, IReadOnlyCollection<string> knownFlags, int start = 1)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);

        for (var i = start; i < args.Length; i++)
        {
            var token = args[i];

            if (!token.StartsWith("--", StringComparison.Ordinal))
            {
                return ParseResult.Failure(
                    $"Unexpected argument '{token}'. Every value must follow its flag, as --flag value.");
            }

            var name = token[2..];
            string? value = null;

            // --flag=value is the reflex form for anyone used to other CLIs. Accepting it removes the
            // footgun outright rather than trading it for an error the operator has to read.
            var equals = name.IndexOf('=', StringComparison.Ordinal);
            if (equals >= 0)
            {
                value = name[(equals + 1)..];
                name = name[..equals];
            }

            if (name.Length == 0)
                return ParseResult.Failure($"'{token}' is not a valid flag.");

            if (!knownFlags.Contains(name, StringComparer.Ordinal))
            {
                return ParseResult.Failure(
                    $"Unknown flag '--{name}'. Known flags: {string.Join(", ", knownFlags.Select(f => "--" + f))}.");
            }

            if (value is null)
            {
                // A flag at the end of the line, or one followed by another flag, lost its value —
                // most likely to shell mangling. That is a mistake to report, never one to absorb.
                if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    return ParseResult.Failure($"--{name} needs a value, as --{name} <value>.");

                value = args[i + 1];
                i++;
            }

            values[name] = value;
        }

        return ParseResult.Success(new CommandLineOptions(values));
    }

    /// <summary>The raw value for <paramref name="name"/>, or <c>null</c> if the flag was not supplied.</summary>
    public string? Get(string name) => _values.TryGetValue(name, out var value) ? value : null;

    /// <summary>Whether the flag was supplied at all.</summary>
    public bool Has(string name) => _values.ContainsKey(name);

    /// <summary>
    /// The value parsed as a non-negative whole number. Absent is success with a null value; present
    /// but unparseable, or negative, is an error — never a fallback.
    /// </summary>
    public IntResult GetInt(string name)
    {
        var raw = Get(name);
        if (raw is null)
            return IntResult.Success(null);

        if (!int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
            return IntResult.Failure($"--{name} must be a whole number; got '{raw}'.");

        if (parsed < 0)
            return IntResult.Failure($"--{name} must not be negative; got {parsed}.");

        return IntResult.Success(parsed);
    }
}
