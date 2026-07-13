using System.ComponentModel.DataAnnotations;
using EclipsVault.Core.Application.ServiceAccounts;
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Web.Models;

public sealed class CreateServiceAccountViewModel
{
    [Required]
    [StringLength(64, MinimumLength = 3)]
    [RegularExpression(@"^[a-zA-Z0-9_\-\.]+$", ErrorMessage = "Use letters, digits, underscores, hyphens or dots.")]
    [Display(Name = "Name")]
    public string Name { get; set; } = string.Empty;

    [Display(Name = "Clearance level")]
    public ClearanceLevel Clearance { get; set; } = ClearanceLevel.Standard;

    [Required]
    [StringLength(64)]
    [Display(Name = "Project key")]
    public string ProjectKey { get; set; } = string.Empty;
}

public sealed class ServiceAccountDetailsViewModel
{
    public ServiceAccountDetailsDto Account { get; init; } = null!;

    /// <summary>The raw token for a key just issued — shown once, carried via TempData.</summary>
    public string? NewlyIssuedToken { get; init; }
}
