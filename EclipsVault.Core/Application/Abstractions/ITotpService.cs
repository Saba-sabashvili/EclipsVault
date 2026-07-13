namespace EclipsVault.Core.Application.Abstractions;

/// <summary>RFC 6238 time-based one-time passwords (second authentication factor).</summary>
public interface ITotpService
{
    /// <summary>Generates a new Base32-encoded shared secret.</summary>
    string GenerateSecret();

    bool ValidateCode(string secretBase32, string code);

    /// <summary>Builds the otpauth:// URI consumed by authenticator apps.</summary>
    string BuildOtpAuthUri(string secretBase32, string accountName);
}
