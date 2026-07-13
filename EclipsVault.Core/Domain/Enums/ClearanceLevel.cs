namespace EclipsVault.Core.Domain.Enums;

/// <summary>Clearance held by a staff member. Compared numerically against a secret's <see cref="SensitivityLevel"/>.</summary>
public enum ClearanceLevel
{
    Standard = 1,
    Elevated = 2,
    Secret = 3,
    TopSecret = 4
}
