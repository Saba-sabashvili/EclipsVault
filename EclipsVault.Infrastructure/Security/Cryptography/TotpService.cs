using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// RFC 6238 TOTP: HMAC-SHA1, 30-second step, 6 digits, with a ±1 step drift window.
/// Code comparison is constant-time.
/// </summary>
public sealed class TotpService : ITotpService
{
    private const string Issuer = "EclipsVault";
    private const int StepSeconds = 30;
    private const int Digits = 6;
    private const int DriftSteps = 1;
    private const int SecretBytes = 20;

    private readonly TimeProvider _clock;

    public TotpService(TimeProvider clock) => _clock = clock;

    public string GenerateSecret()
        => Base32.Encode(RandomNumberGenerator.GetBytes(SecretBytes));

    public bool TryValidateCode(string secretBase32, string code, long? lastUsedStep, out long matchedStep)
    {
        matchedStep = 0;

        code = code.Trim();
        if (code.Length != Digits || !code.All(char.IsAsciiDigit))
        {
            return false;
        }

        byte[] key;
        try
        {
            key = Base32.Decode(secretBase32);
        }
        catch (FormatException)
        {
            return false;
        }

        var currentStep = _clock.GetUtcNow().ToUnixTimeSeconds() / StepSeconds;
        var provided = Encoding.ASCII.GetBytes(code);

        for (var drift = -DriftSteps; drift <= DriftSteps; drift++)
        {
            var step = currentStep + drift;

            // Single-use: a step at or below the last accepted one has already been spent. Checked
            // before the comparison so a replay costs the same work as a wrong code.
            if (lastUsedStep is { } last && step <= last)
            {
                continue;
            }

            var expected = Encoding.ASCII.GetBytes(ComputeCode(key, step));
            if (CryptographicOperations.FixedTimeEquals(expected, provided))
            {
                matchedStep = step;
                return true;
            }
        }

        return false;
    }

    public string BuildOtpAuthUri(string secretBase32, string accountName)
        => $"otpauth://totp/{Uri.EscapeDataString(Issuer)}:{Uri.EscapeDataString(accountName)}" +
           $"?secret={secretBase32}&issuer={Uri.EscapeDataString(Issuer)}&algorithm=SHA1&digits={Digits}&period={StepSeconds}";

    private static string ComputeCode(byte[] key, long timestep)
    {
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, timestep);

        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(counter.ToArray());

        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24)
                     | (hash[offset + 1] << 16)
                     | (hash[offset + 2] << 8)
                     | hash[offset + 3];

        return (binary % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
    }
}

/// <summary>RFC 4648 Base32 (no padding), as consumed by authenticator apps.</summary>
internal static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(byte[] data)
    {
        var sb = new StringBuilder((data.Length * 8 + 4) / 5);
        int bits = 0, value = 0;

        foreach (var b in data)
        {
            value = (value << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(Alphabet[(value >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            sb.Append(Alphabet[(value << (5 - bits)) & 31]);
        }

        return sb.ToString();
    }

    public static byte[] Decode(string encoded)
    {
        var output = new List<byte>(encoded.Length * 5 / 8);
        int bits = 0, value = 0;

        foreach (var raw in encoded)
        {
            if (raw == '=' || raw == ' ')
            {
                continue;
            }

            var index = Alphabet.IndexOf(char.ToUpperInvariant(raw));
            if (index < 0)
            {
                throw new FormatException($"Invalid Base32 character '{raw}'.");
            }

            value = (value << 5) | index;
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)((value >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }

        return [.. output];
    }
}
