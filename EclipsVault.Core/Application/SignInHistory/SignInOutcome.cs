namespace EclipsVault.Core.Application.SignInHistory;

/// <summary>How a single sign-in-related event turned out.</summary>
public enum SignInOutcome
{
    /// <summary>Authentication succeeded (password+MFA, passkey, recovery code, or a passed step-up).</summary>
    Success,

    /// <summary>An authentication attempt was rejected (wrong password, bad code, failed step-up).</summary>
    Failed,

    /// <summary>The account was locked after repeated failures — access was blocked, not merely refused.</summary>
    Blocked,

    /// <summary>An informational state change (e.g. the account was unlocked). No credential was presented.</summary>
    Info
}
