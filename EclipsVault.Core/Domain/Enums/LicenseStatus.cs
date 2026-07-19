namespace EclipsVault.Core.Domain.Enums;

/// <summary>The outcome of verifying a license token. Only <see cref="Valid"/> is fully licensed.</summary>
public enum LicenseStatus
{
    Missing = 0,
    Malformed = 1,
    InvalidSignature = 2,
    Expired = 3,
    Valid = 4
}
