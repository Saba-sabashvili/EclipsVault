namespace EclipsVault.Core.Application.SecurityCheckup;

/// <summary>
/// Where a control is fixed, named in the domain's own terms. The Web layer maps this to a
/// concrete route — Core stays free of any MVC/URL concern.
/// </summary>
public enum RemediationArea
{
    None,
    Profile,
    BackupCodes,
    SignedInDevices
}
