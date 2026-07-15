namespace EclipsVault.Core.Application.SecurityCheckup;

/// <summary>Stable identity of each control, so views/tests can refer to one without matching on prose.</summary>
public enum SecurityCheckKind
{
    TwoStepSignIn,
    BackupCodes,
    Passkey,
    SignedInDevices
}
