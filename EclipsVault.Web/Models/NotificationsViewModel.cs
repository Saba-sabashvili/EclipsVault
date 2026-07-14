using EclipsVault.Core.Application.Notifications;

namespace EclipsVault.Web.Models;

/// <summary>The notification outbox plus the current delivery configuration, so an admin can
/// tell at a glance whether emails are actually being sent and where.</summary>
public sealed class NotificationsViewModel
{
    public IReadOnlyList<EmailLogDto> Outbox { get; init; } = [];

    /// <summary>False when <c>Email:Enabled</c> is off — notifications are recorded as suppressed, never sent.</summary>
    public bool Enabled { get; init; }

    /// <summary>The configured transport: "Log" (dev, recorded only) or "Smtp".</summary>
    public string Transport { get; init; } = "Log";

    /// <summary>"host:port" of the SMTP server when the transport is SMTP; null otherwise.</summary>
    public string? SmtpTarget { get; init; }

    public bool IsSmtp => string.Equals(Transport, "Smtp", StringComparison.OrdinalIgnoreCase);
}
