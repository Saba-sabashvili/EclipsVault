namespace EclipsVault.Core.Application.SignInHistory;

/// <summary>Which credential the attempt used, so the timeline reads clearly.</summary>
public enum SignInMethod
{
    Password,
    TwoFactor,
    Passkey,
    RecoveryCode,
    StepUp,
    System
}
