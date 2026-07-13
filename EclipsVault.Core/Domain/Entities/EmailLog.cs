using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// One row in the notification outbox: a record of an email the vault composed and tried
/// to deliver, with its transport and outcome. Persisted regardless of the transport so the
/// admin Notifications page shows exactly what was sent (or attempted), even in a dev setup
/// where the transport only logs.
/// </summary>
public class EmailLog
{
    public Guid Id { get; set; }

    public string ToAddress { get; set; } = string.Empty;

    public string Subject { get; set; } = string.Empty;

    public string Body { get; set; } = string.Empty;

    /// <summary>The domain event that triggered it (e.g. "AccessRequestApproved").</summary>
    public string EventType { get; set; } = string.Empty;

    /// <summary>The transport that handled it ("Smtp", "Log").</summary>
    public string Transport { get; set; } = string.Empty;

    public EmailDeliveryStatus Status { get; set; }

    public string? Error { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }
}
