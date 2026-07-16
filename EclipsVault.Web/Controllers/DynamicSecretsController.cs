using EclipsVault.Core.Application.Abac;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Core.Domain.Exceptions;
using EclipsVault.Web.Authorization;
using EclipsVault.Web.Extensions;
using EclipsVault.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

/// <summary>
/// Dynamic secrets: credentials the vault mints on a real backend when you ask, and destroys when
/// the lease ends. Nothing here is stored — the value is shown once and is unrecoverable after.
///
/// Every role is gated by the same ABAC handler that guards stored secrets, so the list shows only
/// what the caller could actually issue, and issuing re-checks rather than trusting that filter.
/// </summary>
public sealed class DynamicSecretsController : VaultController
{
    private const string IssuedTempDataKey = "DynamicSecrets.Issued";

    private readonly IDynamicSecretService _dynamicSecrets;
    private readonly IAuthorizationService _authorization;
    private readonly ILogger<DynamicSecretsController> _logger;

    public DynamicSecretsController(
        IDynamicSecretService dynamicSecrets,
        IAuthorizationService authorization,
        ILogger<DynamicSecretsController> logger)
    {
        _dynamicSecrets = dynamicSecrets;
        _authorization = authorization;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken ct)
        => View(await BuildAsync(null, ct));

    [HttpPost]
    public async Task<IActionResult> Issue(IssueCredentialViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid)
        {
            this.FlashError("Enter a lease length between 1 and 1440 minutes.");
            return RedirectToAction(nameof(Index));
        }

        var role = await _dynamicSecrets.FindRoleAsync(form.RoleId, ct);
        if (role is null)
        {
            this.FlashError("That role no longer exists.");
            return RedirectToAction(nameof(Index));
        }

        // Re-check on the way in: the list is filtered by the same policy, but a filtered list is a
        // convenience, never the enforcement point.
        if (!await CanIssueAsync(role))
        {
            _logger.LogWarning(
                "User {Username} was denied a dynamic credential for role {RoleName}", CurrentUsername(), role.Name);
            this.FlashError($"Your clearance and project do not permit issuing '{role.Name}'.");
            return RedirectToAction(nameof(Index));
        }

        try
        {
            var issued = await _dynamicSecrets.IssueAsync(role.Id, form.TtlMinutes, ct);

            // Ride TempData across the redirect: the credential exists only in this response and is
            // never persisted, so it must survive exactly one render and no more.
            TempData[IssuedTempDataKey] = issued.LeaseId.ToString();
            return View(nameof(Index), await BuildAsync(issued, ct));
        }
        catch (VaultAdminException ex)
        {
            this.FlashError(ex.Message);
            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex)
        {
            // A backend that refuses is an operational fault, not a user error: say so plainly
            // rather than leaking the server's message onto the page.
            _logger.LogError(ex, "Minting a dynamic credential for role {RoleName} failed", role.Name);
            this.FlashError($"The backend refused to mint a credential for '{role.Name}'. Nothing was issued.");
            return RedirectToAction(nameof(Index));
        }
    }

    [HttpPost]
    public async Task<IActionResult> Revoke(Guid id, CancellationToken ct)
    {
        var revoked = await _dynamicSecrets.RevokeAsync(id, CurrentUserId(), IsAdmin(), ct);
        if (revoked)
        {
            this.FlashSuccess("Credential handed back — it no longer works.");
        }
        else
        {
            // One message for unknown / closed / someone else's, matching the service's
            // indistinguishable "no".
            this.FlashError("That lease is not active, or is not yours to revoke.");
        }

        return RedirectToAction(nameof(Index));
    }

    private async Task<DynamicSecretsViewModel> BuildAsync(IssuedCredentialDto? issued, CancellationToken ct)
    {
        var roles = await _dynamicSecrets.ListRolesAsync(ct);
        var permitted = new List<DynamicSecretRoleDto>(roles.Count);
        foreach (var role in roles)
        {
            if (role.IsEnabled && await CanIssueAsync(role))
            {
                permitted.Add(role);
            }
        }

        var isAdmin = IsAdmin();
        return new DynamicSecretsViewModel
        {
            Roles = permitted,
            Leases = await _dynamicSecrets.ListLeasesAsync(CurrentUserId(), isAdmin, ct),
            ShowingEveryone = isAdmin,
            Issued = issued
        };
    }

    private async Task<bool> CanIssueAsync(IAbacResource role)
        => (await _authorization.AuthorizeAsync(User, role, VaultPolicies.SecretAccess)).Succeeded;

    private bool IsAdmin()
        => User.HasClaim(VaultClaimTypes.Clearance, ((int)ClearanceLevel.TopSecret).ToString());
}
