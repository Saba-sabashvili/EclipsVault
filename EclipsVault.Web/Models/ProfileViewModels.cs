using System.ComponentModel.DataAnnotations;
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Web.Models;

public sealed class ProfileViewModel
{
    public Guid Id { get; set; }

    /// <summary>Login identity — display-only; it cannot be changed here.</summary>
    public string Username { get; set; } = string.Empty;

    public ClearanceLevel Clearance { get; set; }

    public string ProjectKey { get; set; } = string.Empty;

    public bool TotpEnabled { get; set; }

    public bool HasCustomAvatar { get; set; }

    /// <summary>Registered passkeys, populated by the controller (not part of the edit form).</summary>
    public IReadOnlyList<PasskeySummary> Passkeys { get; set; } = [];

    /// <summary>Unused MFA recovery codes the user currently holds; populated by the controller.</summary>
    public int RecoveryCodesRemaining { get; set; }

    [Required]
    [StringLength(64, MinimumLength = 1)]
    [Display(Name = "Display name")]
    public string DisplayName { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    [StringLength(256)]
    [Display(Name = "Email")]
    public string Email { get; set; } = string.Empty;

    public static ProfileViewModel From(ProfileDto dto) => new()
    {
        Id = dto.Id,
        Username = dto.Username,
        Clearance = dto.Clearance,
        ProjectKey = dto.ProjectKey,
        TotpEnabled = dto.TotpEnabled,
        HasCustomAvatar = dto.HasCustomAvatar,
        DisplayName = dto.DisplayName,
        Email = dto.Email
    };
}

/// <summary>Carries a freshly generated set of recovery codes to the one-time display page.</summary>
public sealed class RecoveryCodesViewModel
{
    public IReadOnlyList<string> Codes { get; set; } = [];
}

/// <summary>Body of the live "is this password breached?" check.</summary>
public sealed record PasswordCheckRequest(string? Password);

public sealed class ChangePasswordViewModel
{
    [Required]
    [DataType(DataType.Password)]
    [Display(Name = "Current password")]
    public string CurrentPassword { get; set; } = string.Empty;

    [Required]
    [StringLength(256, MinimumLength = 12, ErrorMessage = "Your new password must be at least 12 characters.")]
    [DataType(DataType.Password)]
    [Display(Name = "New password")]
    public string NewPassword { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    [Compare(nameof(NewPassword), ErrorMessage = "The passwords do not match.")]
    [Display(Name = "Confirm new password")]
    public string ConfirmPassword { get; set; } = string.Empty;
}
