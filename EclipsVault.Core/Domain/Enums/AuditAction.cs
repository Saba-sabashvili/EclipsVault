namespace EclipsVault.Core.Domain.Enums;

/// <summary>Every action the immutable audit trail can record.</summary>
public enum AuditAction
{
    SecretCreated = 1,
    SecretMetadataViewed = 2,
    SecretRevealed = 3,
    SecretUpdated = 4,
    SecretDeleted = 5,
    SecretShredded = 6,
    SecretRotated = 7,
    SecretVersionRevealed = 8,
    SecretVersionRestored = 9,
    SecretShared = 14,
    SecretShareRevoked = 15,
    LoginFailed = 10,
    LoginSucceeded = 11,
    TotpFailed = 12,
    TotpEnrolled = 13,
    HoneyTokenTripped = 20,
    SessionRevoked = 21,
    UserCreated = 30,
    UserDeleted = 31,
    UserTotpReset = 32,
    AccountLockedOut = 33,
    AccountUnlocked = 34,
    TrustedNetworkAdded = 40,
    TrustedNetworkRemoved = 41,
    IpRangeUnblocked = 42,
    BreakGlassRecovery = 43,

    // Self-service profile actions.
    ProfileUpdated = 50,
    AvatarUpdated = 51,
    AvatarRemoved = 52,
    PasswordChanged = 53,
    SelfMfaReset = 54,
    SessionsRevokedSelf = 55,
    PasskeyRegistered = 56,
    PasskeyRemoved = 57,
    PasskeyLogin = 58,

    // Administrative account actions.
    UserRoleChanged = 60,
    UserDisabled = 61,
    UserEnabled = 62,
    UserForceLoggedOut = 63,

    // Service accounts & API keys.
    ServiceAccountCreated = 70,
    ServiceAccountDeleted = 71,
    ServiceAccountDisabled = 72,
    ServiceAccountEnabled = 73,
    ApiKeyIssued = 74,
    ApiKeyRevoked = 75,

    // Self-service access requests.
    AccessRequested = 80,
    AccessRequestApproved = 81,
    AccessRequestRejected = 82,
    AccessRequestCancelled = 83,

    // Key lifecycle.
    KekRotated = 90,

    // MFA recovery ("backup") codes.
    RecoveryCodesGenerated = 100,
    RecoveryCodeUsed = 101
}
