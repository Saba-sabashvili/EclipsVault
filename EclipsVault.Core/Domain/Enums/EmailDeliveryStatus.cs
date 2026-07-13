namespace EclipsVault.Core.Domain.Enums;

/// <summary>Outcome of an attempt to deliver a notification email.</summary>
public enum EmailDeliveryStatus
{
    /// <summary>Handed to the transport without error.</summary>
    Sent = 0,

    /// <summary>The transport threw; the error is recorded on the outbox row.</summary>
    Failed = 1,

    /// <summary>Delivery was not attempted because notifications are disabled.</summary>
    Suppressed = 2
}
