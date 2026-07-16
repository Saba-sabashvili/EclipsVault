using System.ComponentModel.DataAnnotations;
using EclipsVault.Core.Application.Secrets;
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Web.Models;

/// <summary>IsDecoy is only ever set for TopSecret administrators — ordinary users
/// must see decoys as indistinguishable from real secrets.</summary>
public sealed record SecretListItemViewModel(
    Guid Id,
    string Name,
    string ProjectKey,
    SecretEnvironment Environment,
    SensitivityLevel Sensitivity,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    bool IsDecoy);

public sealed class SecretDetailsViewModel
{
    public Guid Id { get; init; }

    public string Name { get; init; } = string.Empty;

    public string ProjectKey { get; init; } = string.Empty;

    public SecretEnvironment Environment { get; init; }

    public SensitivityLevel Sensitivity { get; init; }

    public string Algorithm { get; init; } = string.Empty;

    public DateTimeOffset CreatedAtUtc { get; init; }

    public DateTimeOffset? UpdatedAtUtc { get; init; }

    public DateTimeOffset? ExpiresAtUtc { get; init; }

    /// <summary>Populated only for the single response following an authorized reveal.</summary>
    public string? RevealedValue { get; init; }

    /// <summary>Label of what was revealed ("current value" or "version N"); null when nothing is revealed.</summary>
    public string? RevealedLabel { get; init; }

    /// <summary>Archived (superseded) values, newest first.</summary>
    public IReadOnlyList<SecretVersionDto> Versions { get; init; } = [];

    /// <summary>True when the current user may manage sharing (admin, or a member of the secret's project).</summary>
    public bool CanShare { get; init; }

    /// <summary>Active access grants on this secret (populated only when <see cref="CanShare"/>).</summary>
    public IReadOnlyList<SecretGrantDto> Grants { get; init; } = [];

    /// <summary>True when a reveal was attempted but a fresh re-authentication is required first.</summary>
    public bool StepUpRequired { get; init; }

    /// <summary>Set when a submitted step-up code was wrong.</summary>
    public string? StepUpError { get; init; }

    /// <summary>Carries the archived version being revealed through the step-up round-trip (null for the current value).</summary>
    public Guid? StepUpVersionId { get; init; }

    /// <summary>The configured freshness window, for the step-up prompt's explanation.</summary>
    public int StepUpMaxAgeMinutes { get; init; }
}

public sealed class ShareSecretViewModel
{
    public Guid SecretId { get; set; }

    [Required]
    [StringLength(256)]
    [Display(Name = "User (username or email)")]
    public string GranteeUsernameOrEmail { get; set; } = string.Empty;

    [Range(0, 3650)]
    [Display(Name = "Access expires in days (0 = no expiry)")]
    public int TtlDays { get; set; }
}

public sealed class RotateSecretViewModel
{
    public Guid Id { get; set; }

    [Required]
    [StringLength(8192)]
    [DataType(DataType.MultilineText)]
    [Display(Name = "New value")]
    public string NewValue { get; set; } = string.Empty;

    [StringLength(256)]
    [Display(Name = "Change note (optional)")]
    public string? ChangeNote { get; set; }

    /// <summary>Null leaves the existing expiry alone; a value resets it to that many days from now.</summary>
    [Range(1, 3650)]
    [Display(Name = "Renew for (days)")]
    public int? RenewTtlDays { get; set; }
}

public sealed class CreateSecretViewModel
{
    [Required]
    [StringLength(128, MinimumLength = 3)]
    [RegularExpression(@"^[A-Za-z0-9_\-\.]+$", ErrorMessage = "Use letters, digits, underscores, hyphens or dots.")]
    [Display(Name = "Name")]
    public string Name { get; set; } = string.Empty;

    [Required]
    [StringLength(8192)]
    [DataType(DataType.MultilineText)]
    [Display(Name = "Secret value")]
    public string Value { get; set; } = string.Empty;

    [Required]
    [StringLength(64)]
    [Display(Name = "Project key")]
    public string ProjectKey { get; set; } = string.Empty;

    [Display(Name = "Environment")]
    public SecretEnvironment Environment { get; set; } = SecretEnvironment.Development;

    [Display(Name = "Sensitivity")]
    public SensitivityLevel Sensitivity { get; set; } = SensitivityLevel.Internal;

    [Range(0, 3650)]
    [Display(Name = "TTL in days (0 = never expires)")]
    public int TtlDays { get; set; }
}
