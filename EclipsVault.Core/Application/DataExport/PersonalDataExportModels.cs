namespace EclipsVault.Core.Application.DataExport;

/// <summary>
/// A portable, human-readable copy of the account and security data EclipsVault holds about one
/// user (right-of-access / data-portability). It is deliberately <b>metadata only</b> — there is no
/// field anywhere in this tree that can carry a secret value, ciphertext, key material, a password,
/// a TOTP seed, or a backup code. Secret <i>values</i> are encrypted and access-controlled and are
/// never part of a personal-data export; only counts and non-sensitive attributes appear here.
/// </summary>
public sealed record PersonalDataExport(
    DateTimeOffset GeneratedAtUtc,
    string SchemaVersion,
    ExportAccount Account,
    ExportSecurity Security,
    IReadOnlyList<ExportDevice> SignedInDevices,
    IReadOnlyList<ExportAccessRequest> AccessRequests,
    IReadOnlyList<ExportActivityEntry> RecentActivity,
    string Notice)
{
    /// <summary>The schema version stamped into every export, so a reader can evolve with the shape.</summary>
    public const string CurrentSchemaVersion = "1.0";

    /// <summary>The fixed disclosure printed into every export and shown on the page.</summary>
    public const string StandardNotice =
        "This file contains the account and security metadata EclipsVault holds about you. " +
        "It never includes secret values, passwords, authenticator seeds, or backup codes — " +
        "those are encrypted and access-controlled and are never exported.";
}

/// <summary>Identity and directory attributes. No credential material.</summary>
public sealed record ExportAccount(
    string Username,
    string DisplayName,
    string Email,
    string Clearance,
    string ProjectKey,
    bool HasCustomAvatar);

/// <summary>Security posture — presence and counts only, never the secrets behind them.</summary>
public sealed record ExportSecurity(
    bool TwoStepEnabled,
    int BackupCodesRemaining,
    IReadOnlyList<ExportPasskey> Passkeys);

/// <summary>A registered passkey: its nickname and when it was added (never the credential).</summary>
public sealed record ExportPasskey(string Nickname, DateTimeOffset CreatedAtUtc);

/// <summary>One active "signed-in device" as shown on the sessions page.</summary>
public sealed record ExportDevice(
    string Device,
    string IpAddress,
    DateTimeOffset SignedInAtUtc,
    DateTimeOffset LastActiveAtUtc);

/// <summary>One access request the user has filed, with its outcome.</summary>
public sealed record ExportAccessRequest(
    string SecretName,
    string ProjectKey,
    string Status,
    string Reason,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? DecidedAtUtc,
    string? DecidedBy);

/// <summary>One entry from the user's own activity trail, in plain language.</summary>
public sealed record ExportActivityEntry(
    DateTimeOffset TimestampUtc,
    string Action,
    string? Resource,
    string SourceIp);
