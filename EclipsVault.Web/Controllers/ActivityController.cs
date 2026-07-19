using EclipsVault.Web.Models;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

/// <summary>
/// The signed-in user's personal security-activity feed: a plain-language, paged view of the
/// audit trail restricted to the caller's own actions. Available to every authenticated user
/// (not just admins) so anyone can review their own sign-ins, reveals, and account changes and
/// spot anything they didn't do. Read-only; it discloses nothing about other users.
/// </summary>
public sealed class ActivityController : VaultController
{
    private readonly IActivityService _activity;

    public ActivityController(IActivityService activity) => _activity = activity;

    [HttpGet]
    public async Task<IActionResult> Index(int page = 1, CancellationToken ct = default)
    {
        var feed = await _activity.GetForUserAsync(CurrentUserId(), page, ActivityService.DefaultPageSize, ct);
        return View(new ActivityIndexViewModel { Feed = feed });
    }

}
