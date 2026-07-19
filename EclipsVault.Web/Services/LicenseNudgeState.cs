using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Web.Services;

/// <summary>
/// The precomputed inputs to the licensing banner: the license status and any premium features that
/// are switched on in configuration but not covered by the current tier. Built once at startup from
/// the singleton <see cref="ILicenseState"/>. Soft — it only decides whether a reminder is shown,
/// never what the vault does.
/// </summary>
public sealed record LicenseNudgeState(
    LicenseStatus Status,
    string Message,
    IReadOnlyList<string> PremiumFeaturesBeyondTier)
{
    /// <summary>Show the banner when the license is not Valid, or a premium feature is in use beyond the tier.</summary>
    public bool ShowBanner => Status != LicenseStatus.Valid || PremiumFeaturesBeyondTier.Count > 0;

    /// <summary>
    /// Pure: from the resolved license and the premium features switched on in configuration, keep the
    /// ones the current license does not grant. Everything keeps working regardless — this only
    /// decides what the banner says.
    /// </summary>
    public static LicenseNudgeState From(ILicenseState license, IEnumerable<string> configActivePremiumFeatures)
    {
        var beyond = configActivePremiumFeatures.Where(feature => !license.Allows(feature)).ToArray();
        return new LicenseNudgeState(license.Status, license.Message, beyond);
    }
}
