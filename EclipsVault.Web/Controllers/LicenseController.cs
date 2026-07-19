using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Web.Authorization;
using EclipsVault.Web.Models;
using EclipsVault.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

/// <summary>
/// Shows how this vault is licensed and how to install or renew a license. Read-only and admin-only.
/// Licensing is soft — this page reports state, it never restricts the vault.
/// </summary>
[Authorize(Policy = VaultPolicies.AdminOnly)]
public sealed class LicenseController : Controller
{
    private readonly ILicenseState _license;
    private readonly LicenseNudgeState _nudge;

    public LicenseController(ILicenseState license, LicenseNudgeState nudge)
    {
        _license = license;
        _nudge = nudge;
    }

    [HttpGet]
    public IActionResult Index()
        => View(new LicenseViewModel(
            _license.Status, _license.Message, _license.Claims, _nudge.PremiumFeaturesBeyondTier));
}
