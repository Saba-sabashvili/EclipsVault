using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Web.Models;

/// <summary>What the admin License page renders: the resolved status and message, the claims (only
/// present for a trusted license), and any premium features in use beyond the tier.</summary>
public sealed record LicenseViewModel(
    LicenseStatus Status,
    string Message,
    LicenseClaims? Claims,
    IReadOnlyList<string> PremiumFeaturesBeyondTier);
