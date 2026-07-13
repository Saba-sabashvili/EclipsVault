namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Screens candidate passwords against a corpus of known-compromised and commonly-used
/// values, so a password exposed in a public breach can never be set. Implements the
/// NIST SP 800-63B §5.1.1.2 requirement to compare prospective secrets against a
/// blocklist (see also OWASP ASVS 2.1.7). The check is offline and constant with
/// respect to the wider system — it never leaves the process.
/// </summary>
public interface IBreachedPasswordScreen
{
    /// <summary>
    /// True when the password appears in the compromised-password corpus and must be
    /// rejected. Comparison is case-insensitive so trivial case variants of a listed
    /// value are also caught.
    /// </summary>
    bool IsCompromised(string password);

    /// <summary>Number of entries loaded — surfaced for diagnostics/admin visibility.</summary>
    int CorpusSize { get; }
}
