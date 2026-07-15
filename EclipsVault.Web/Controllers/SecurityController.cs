using System.Security.Claims;
using EclipsVault.Web.Models;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

/// <summary>
/// The signed-in user's personal "security checkup": a scored, plain-language view of their own
/// account posture — two-step sign-in, backup codes, passkeys, and live devices — with the single
/// most important next step surfaced first. Available to every authenticated user (not just admins)
/// and strictly self-scoped: it reads only the caller's own posture and discloses nothing about
/// anyone else. Read-only — every remediation link points at an existing self-service page.
/// </summary>
public sealed class SecurityController : Controller
{
    private readonly ISecurityCheckupService _checkup;

    public SecurityController(ISecurityCheckupService checkup) => _checkup = checkup;

    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var checkup = await _checkup.GetForUserAsync(CurrentUserId(), ct);
        if (checkup is null)
        {
            // The account backing this session is gone — send the stale cookie to sign out.
            return RedirectToAction("Logout", "Account");
        }

        return View(new SecurityCheckupViewModel { Checkup = checkup });
    }

    private Guid CurrentUserId()
        => Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : Guid.Empty;
}
