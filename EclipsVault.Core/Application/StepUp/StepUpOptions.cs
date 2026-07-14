using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.StepUp;

/// <summary>
/// Policy for step-up (re-)authentication: revealing a sufficiently sensitive secret requires
/// a fresh authenticator check when the session's last strong authentication is too old. Maps
/// to NIST SP 800-63B §4.2.3 (reauthentication) and PCI-DSS re-auth for sensitive access.
/// </summary>
public sealed class StepUpOptions
{
    public const string SectionName = "StepUp";

    /// <summary>Reveals of secrets at or above this sensitivity require a fresh re-authentication.</summary>
    public SensitivityLevel MinimumSensitivity { get; set; } = SensitivityLevel.Secret;

    /// <summary>How recent the last strong authentication must be, in minutes, to skip the step-up.</summary>
    public int MaxAuthAgeMinutes { get; set; } = 10;
}
