using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Notifications;

/// <summary>A composed outbound message handed to an <see cref="Abstractions.IEmailSender"/>.</summary>
public sealed record EmailMessage(string To, string Subject, string Body);

/// <summary>An outbox row, projected for the admin Notifications page.</summary>
public sealed record EmailLogDto(
    Guid Id,
    string ToAddress,
    string Subject,
    string Body,
    string EventType,
    string Transport,
    EmailDeliveryStatus Status,
    string? Error,
    DateTimeOffset CreatedAtUtc);

/// <summary>Notification behaviour bound from configuration. When disabled, sends are recorded as suppressed.</summary>
public sealed record NotificationOptions(bool Enabled)
{
    public static readonly NotificationOptions Default = new(true);
}
