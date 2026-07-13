using System.Reflection;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Screens passwords against a compromised-password corpus bundled with the assembly as
/// an embedded resource. The list is loaded once into a case-folded <see cref="HashSet{T}"/>
/// for O(1), allocation-light lookups. Everything stays in-process — no network call, so
/// screening works fully offline and leaks nothing about the candidate.
/// </summary>
public sealed class BundledBreachedPasswordScreen : IBreachedPasswordScreen
{
    private const string ResourceSuffix = ".CompromisedPasswords.txt";

    private readonly HashSet<string> _corpus;

    public BundledBreachedPasswordScreen()
    {
        _corpus = LoadCorpus();
    }

    public int CorpusSize => _corpus.Count;

    public bool IsCompromised(string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return false;
        }

        // Fold to the same canonical form the corpus is stored in, so trivial case
        // variants ("Password1234" vs "password1234") are caught too.
        return _corpus.Contains(password.Trim().ToLowerInvariant());
    }

    private static HashSet<string> LoadCorpus()
    {
        var assembly = typeof(BundledBreachedPasswordScreen).Assembly;
        var resourceName = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith(ResourceSuffix, StringComparison.Ordinal))
            ?? throw new InvalidOperationException(
                $"Compromised-password corpus (a resource ending '{ResourceSuffix}') was not embedded in the assembly.");

        using var stream = assembly.GetManifestResourceStream(resourceName)!;
        using var reader = new StreamReader(stream);

        var set = new HashSet<string>(StringComparer.Ordinal);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var trimmed = line.Trim();
            // Skip blanks and '#' comment/header lines.
            if (trimmed.Length == 0 || trimmed[0] == '#')
            {
                continue;
            }

            set.Add(trimmed.ToLowerInvariant());
        }

        return set;
    }
}
