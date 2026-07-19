using System.Security.Cryptography;

namespace EclipsVault.Core.Application.DynamicSecrets;

/// <summary>
/// Generates the name and password for a dynamic credential.
///
/// Both are drawn from a strictly alphanumeric alphabet on purpose. They end up interpolated into
/// backend DDL (<c>CREATE LOGIN [name] WITH PASSWORD = '...'</c>) which cannot be parameterised, so
/// the only sound defence is that no value can carry a quote, bracket, or escape in the first
/// place. <see cref="CredentialStatementTemplate"/> re-checks that invariant at substitution time
/// rather than trusting this to be the only caller.
/// </summary>
public static class CredentialMint
{
    private const string Lower = "abcdefghijkmnopqrstuvwxyz";
    private const string Upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string Digits = "23456789";
    private const string Alphabet = Lower + Upper + Digits;

    private const int PasswordLength = 40;
    private const int IdentitySuffixLength = 10;

    /// <summary>Longest role fragment kept in a login name (SQL Server caps identifiers at 128).</summary>
    private const int MaxRoleFragment = 24;

    /// <summary>
    /// A unique login name for one lease, e.g. <c>ev_phoenix_db_reader_k3mq8x2ptw</c>. The prefix
    /// makes vault-minted principals obvious to a DBA reading the server's logins.
    /// </summary>
    public static string NewIdentity(string roleName)
    {
        var fragment = new string(roleName
            .ToLowerInvariant()
            .Select(c => char.IsAsciiLetterOrDigit(c) ? c : '_')
            .Take(MaxRoleFragment)
            .ToArray())
            .Trim('_');

        if (fragment.Length == 0)
        {
            fragment = "role";
        }

        return $"ev_{fragment}_{RandomNumberGenerator.GetString(Alphabet, IdentitySuffixLength)}";
    }

    /// <summary>
    /// A 40-character alphanumeric password. Guaranteeing one of each case plus a digit satisfies
    /// SQL Server's complexity policy (three of four categories) without reaching for the symbols
    /// that would break out of a quoted literal.
    /// </summary>
    public static string NewPassword()
    {
        Span<char> buffer = stackalloc char[PasswordLength];
        buffer[0] = RandomNumberGenerator.GetString(Lower, 1)[0];
        buffer[1] = RandomNumberGenerator.GetString(Upper, 1)[0];
        buffer[2] = RandomNumberGenerator.GetString(Digits, 1)[0];
        RandomNumberGenerator.GetString(Alphabet, PasswordLength - 3).CopyTo(buffer[3..]);
        RandomNumberGenerator.Shuffle(buffer);

        return new string(buffer);
    }
}
