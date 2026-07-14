using EclipsVault.Infrastructure.Notifications;
using EclipsVault.Web.Authorization;
using EclipsVault.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

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
    private readonly EmailOptions _email;

    public NotificationsController(INotificationService notifications, IOptions<EmailOptions> email)
    {
        _notifications = notifications;
        _email = email.Value;
    }

    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken ct)
        => View(new NotificationsViewModel
        {
            Outbox = await _notifications.ListRecentAsync(200, ct),
            Enabled = _email.Enabled,
            Transport = _email.Sender,
            SmtpTarget = string.Equals(_email.Sender, "Smtp", StringComparison.OrdinalIgnoreCase)
                ? $"{_email.Smtp.Host}:{_email.Smtp.Port}"
                : null
        });
}
