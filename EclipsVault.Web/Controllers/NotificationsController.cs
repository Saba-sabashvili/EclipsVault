using EclipsVault.Web.Authorization;
using EclipsVault.Web.Models;
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
    private readonly IEmailTransportStatus _transport;

    public NotificationsController(INotificationService notifications, IEmailTransportStatus transport)
    {
        _notifications = notifications;
        _transport = transport;
    }

    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken ct)
        => View(new NotificationsViewModel
        {
            Outbox = await _notifications.ListRecentAsync(200, ct),
            Enabled = _transport.Enabled,
            Transport = _transport.Transport,
            SmtpTarget = _transport.SmtpTarget
        });
}
