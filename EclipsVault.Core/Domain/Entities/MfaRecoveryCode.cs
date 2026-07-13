namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// A single-use MFA recovery ("backup") code — the NIST SP 800-63B "look-up secret"
/// that lets a user sign in when their authenticator is unavailable. Only a salted
/// Argon2id hash is persisted; the plaintext is shown to the user exactly once, at
/// generation. Redeeming a code stands in for the TOTP step and then permanently
/// consumes it.
/// </summary>
public class MfaRecoveryCode
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public User? User { get; set; }

    /// <summary>Argon2id hash (32 bytes) of the normalized code.</summary>
    public byte[] CodeHash { get; set; } = [];

    /// <summary>Cryptographically random, per-code salt (16 bytes).</summary>
    public byte[] Salt { get; set; } = [];

    public DateTimeOffset CreatedAtUtc { get; set; }

    /// <summary>Set the instant the code is redeemed; a non-null value means it can never be used again.</summary>
    public DateTimeOffset? UsedAtUtc { get; set; }

    public bool IsUsed => UsedAtUtc is not null;
}
