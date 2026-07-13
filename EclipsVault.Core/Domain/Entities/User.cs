using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// A staff member of the vault. Password material is an Argon2id hash plus a unique
/// 16-byte random salt — the raw password is never persisted anywhere.
/// </summary>
public class User
{
    public Guid Id { get; set; }

    /// <summary>Login identity and audit-trail anchor. Immutable once created.</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>Human-friendly name shown across the UI; user-editable.</summary>
    public string DisplayName { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    /// <summary>Argon2id hash (32 bytes).</summary>
    public byte[] PasswordHash { get; set; } = [];

    /// <summary>Cryptographically random, per-user salt (16 bytes).</summary>
    public byte[] PasswordSalt { get; set; } = [];

    /// <summary>Base32-encoded TOTP shared secret. Null until enrollment begins.</summary>
    public string? TotpSecret { get; set; }

    /// <summary>True once the user has proven possession of the authenticator.</summary>
    public bool TotpEnabled { get; set; }

    /// <summary>ABAC subject attribute: clearance held by this user.</summary>
    public ClearanceLevel Clearance { get; set; } = ClearanceLevel.Standard;

    /// <summary>ABAC subject attribute: the project this user is assigned to.</summary>
    public string ProjectKey { get; set; } = string.Empty;

    /// <summary>When true, the account cannot sign in and active sessions are rejected.</summary>
    public bool IsDisabled { get; set; }

    /// <summary>Consecutive failed authentication attempts since the last success; drives lockout.</summary>
    public int FailedAccessCount { get; set; }

    /// <summary>When set and in the future, sign-in is blocked until this instant (brute-force lockout).</summary>
    public DateTimeOffset? LockedUntilUtc { get; set; }

    public bool IsLockedOut(DateTimeOffset nowUtc) => LockedUntilUtc is { } until && until > nowUtc;

    /// <summary>Timestamp of the last custom-avatar change; null means the generated
    /// identicon is in use. Doubles as a cache-busting version for the avatar URL.</summary>
    public DateTimeOffset? AvatarUpdatedAtUtc { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }

    public ICollection<PasskeyCredential> Passkeys { get; set; } = new List<PasskeyCredential>();
}
