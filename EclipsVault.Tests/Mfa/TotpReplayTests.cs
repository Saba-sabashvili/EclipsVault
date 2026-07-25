using System.Security.Cryptography;
using EclipsVault.Infrastructure.Security;
using Xunit;

namespace EclipsVault.Tests.Mfa;

/// <summary>
/// RFC 6238 §5.2: a verifier must not accept the same one-time password twice. A TOTP code stays
/// valid for its whole 30-second step plus the drift window, so without single-use enforcement a
/// code observed once — a phishing proxy, a shoulder-surf, a screenshot pasted into a ticket — can
/// be replayed for roughly ninety seconds. Account lockout does not cover this: lockout counts wrong
/// guesses, and a replayed code is a right one.
///
/// The codes here are computed independently of the service (plain RFC 4226 dynamic truncation), so
/// these test the implementation rather than restating it.
/// </summary>
public class TotpReplayTests
{
    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private const int StepSeconds = 30;

    private static readonly DateTimeOffset T0 =
        DateTimeOffset.FromUnixTimeSeconds(1_700_000_000); // an arbitrary fixed instant

    private static long StepOf(DateTimeOffset at) => at.ToUnixTimeSeconds() / StepSeconds;

    /// <summary>RFC 4226 HOTP over an RFC 6238 time step — written out rather than reused.</summary>
    private static string CodeFor(byte[] key, long step)
    {
        var counter = new byte[8];
        for (var i = 7; i >= 0; i--)
        {
            counter[i] = (byte)(step & 0xFF);
            step >>= 8;
        }

        using var hmac = new HMACSHA1(key);
        var mac = hmac.ComputeHash(counter);
        var offset = mac[^1] & 0x0F;
        var binary = ((mac[offset] & 0x7F) << 24)
                     | (mac[offset + 1] << 16)
                     | (mac[offset + 2] << 8)
                     | mac[offset + 3];
        return (binary % 1_000_000).ToString("D6");
    }

    private static byte[] Base32Decode(string s)
    {
        const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new List<byte>();
        int bits = 0, value = 0;
        foreach (var c in s)
        {
            var index = Alphabet.IndexOf(char.ToUpperInvariant(c));
            if (index < 0) continue;
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

    private static (TotpService Service, FixedClock Clock, string Secret, byte[] Key) NewService()
    {
        var clock = new FixedClock(T0);
        var service = new TotpService(clock);
        var secret = service.GenerateSecret();
        return (service, clock, secret, Base32Decode(secret));
    }

    [Fact]
    public void A_fresh_code_is_accepted_and_reports_its_step()
    {
        var (service, _, secret, key) = NewService();
        var step = StepOf(T0);

        Assert.True(service.TryValidateCode(secret, CodeFor(key, step), lastUsedStep: null, out var matched));
        Assert.Equal(step, matched);
    }

    /// <summary>The fix: the same code, inside its own validity window, must not work twice.</summary>
    [Fact]
    public void The_same_code_is_refused_the_second_time()
    {
        var (service, _, secret, key) = NewService();
        var step = StepOf(T0);
        var code = CodeFor(key, step);

        Assert.True(service.TryValidateCode(secret, code, lastUsedStep: null, out var matched));

        // Same code, same step, clock unmoved — exactly the replay window an observer gets.
        Assert.False(service.TryValidateCode(secret, code, lastUsedStep: matched, out _));
    }

    [Fact]
    public void A_code_from_an_earlier_step_is_refused_after_a_later_one_was_used()
    {
        var (service, clock, secret, key) = NewService();
        var earlier = StepOf(T0);

        clock.Now = T0.AddSeconds(StepSeconds);
        var later = StepOf(clock.Now);
        Assert.True(service.TryValidateCode(secret, CodeFor(key, later), lastUsedStep: null, out var used));
        Assert.Equal(later, used);

        // The previous step is still inside the drift window, but it has been overtaken.
        Assert.False(service.TryValidateCode(secret, CodeFor(key, earlier), lastUsedStep: used, out _));
    }

    [Fact]
    public void The_next_step_is_accepted_after_the_previous_one_was_spent()
    {
        var (service, clock, secret, key) = NewService();
        var first = StepOf(T0);
        Assert.True(service.TryValidateCode(secret, CodeFor(key, first), lastUsedStep: null, out var used));

        clock.Now = T0.AddSeconds(StepSeconds);
        var next = StepOf(clock.Now);
        Assert.True(service.TryValidateCode(secret, CodeFor(key, next), lastUsedStep: used, out var matched));
        Assert.Equal(next, matched);
    }

    [Fact]
    public void The_drift_window_still_accepts_the_adjacent_steps()
    {
        var (service, _, secret, key) = NewService();
        var current = StepOf(T0);

        Assert.True(service.TryValidateCode(secret, CodeFor(key, current - 1), lastUsedStep: null, out _));
        Assert.True(service.TryValidateCode(secret, CodeFor(key, current + 1), lastUsedStep: null, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("abcdef")]
    public void A_malformed_code_is_refused(string code)
    {
        var (service, _, secret, _) = NewService();
        Assert.False(service.TryValidateCode(secret, code, lastUsedStep: null, out _));
    }
}
