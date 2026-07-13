using System.Security.Cryptography;
using System.Text;

namespace EclipsVault.Core.Application.Mfa;

/// <summary>
/// Generates and normalizes MFA recovery codes. Each code is 10 characters drawn from a
/// 32-symbol alphabet with the visually ambiguous letters (I, O) and digits (0, 1)
/// removed — ~50 bits of entropy — shown grouped as <c>XXXXX-XXXXX</c> for legibility.
/// Because that is below the 112-bit threshold in SP 800-63B, codes are stored salted
/// and hashed with a moderate work factor (Argon2id), never in the clear.
/// </summary>
public static class RecoveryCodeFormat
{
    private const string Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private const int CodeLength = 10;

    /// <summary>A new random code in display form (<c>XXXXX-XXXXX</c>).</summary>
    public static string NewCode()
    {
        var chars = new char[CodeLength];
        for (var i = 0; i < CodeLength; i++)
        {
            chars[i] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
        }

        return string.Concat(new string(chars, 0, 5), "-", new string(chars, 5, 5));
    }

    /// <summary>
    /// Strips separators and whitespace and upper-cases the input so the value a user
    /// types compares equal to the code that was hashed regardless of dashes or case.
    /// </summary>
    public static string Normalize(string input)
    {
        var sb = new StringBuilder(CodeLength);
        foreach (var ch in input)
        {
            if (char.IsLetterOrDigit(ch))
            {
                sb.Append(char.ToUpperInvariant(ch));
            }
        }

        return sb.ToString();
    }
}
