using EclipsVault.Web.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

/// <summary>
/// The notification outbox (TopSecret clearance only): every email the vault composed and
/// tried to deliver, with its transport and outcome. Read-only — a delivery record, not a
/// mailbox.
/// </summary>
[Authorize(Policy = VaultPolicies.AdminOnly)]
public sealed class NotificationsController : Controller
{
    private readonly INotificationService _notifications;

    public NotificationsController(INotificationService notifications) => _notifications = notifications;

    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken ct)
        => View(await _notifications.ListRecentAsync(200, ct));
}
