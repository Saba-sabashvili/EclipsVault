namespace EclipsVault.Core.Application.Abstractions;

/// <summary>RFC 6238 time-based one-time passwords (second authentication factor).</summary>
public interface ITotpService
{
    /// <summary>Generates a new Base32-encoded shared secret.</summary>
    string GenerateSecret();

    /// <summary>
    /// Validates a code and reports the time step it matched.
    ///
    /// <paramref name="lastUsedStep"/> is required rather than optional so a caller cannot forget
    /// single-use enforcement: RFC 6238 §5.2 says a verifier must not accept the same one-time
    /// password twice, and a code stays valid for its whole step plus the drift window. Without
    /// this, a code observed once — a phishing proxy, a shoulder-surf, a screenshot in a support
    /// ticket — can be replayed for roughly ninety seconds. Lockout does not help: it counts wrong
    /// guesses, and a replayed code is a right one. A code at or below the last accepted step is
    /// refused; on success the caller must persist <paramref name="matchedStep"/>.
    /// </summary>
    bool TryValidateCode(string secretBase32, string code, long? lastUsedStep, out long matchedStep);

    /// <summary>Builds the otpauth:// URI consumed by authenticator apps.</summary>
    string BuildOtpAuthUri(string secretBase32, string accountName);
}
