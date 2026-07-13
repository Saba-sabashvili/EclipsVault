namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Transport port for outbound email. Implementations do delivery only (SMTP, or a dev
/// logger); composing messages and recording them to the outbox is the notification
/// service's job. Swapping SMTP for a cloud/webhook transport is a config + one-class change.
/// </summary>
public interface IEmailSender
{
    /// <summary>Short transport name recorded on each outbox row ("Smtp", "Log").</summary>
    string Transport { get; }

    /// <summary>Delivers the message, or throws if the transport fails.</summary>
    Task SendAsync(EmailMessage message, CancellationToken ct);
}
