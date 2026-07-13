namespace EclipsVault.Core.Domain.Enums;

/// <summary>Sensitivity classification of a secret. Compared numerically against a user's <see cref="ClearanceLevel"/>.</summary>
public enum SensitivityLevel
{
    Internal = 1,
    Confidential = 2,
    Secret = 3,
    TopSecret = 4
}
