using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Notifications;

/// <summary>
/// Production transport over SMTP. Selected by <c>Email:Sender=Smtp</c>. Any delivery error
/// surfaces to the notification service, which records it as a Failed outbox row (fail-soft).
/// </summary>
public sealed class SmtpEmailSender : IEmailSender
{
    private readonly EmailOptions _options;

    public SmtpEmailSender(IOptions<EmailOptions> options) => _options = options.Value;

    public string Transport => "Smtp";

    public async Task SendAsync(EmailMessage message, CancellationToken ct)
    {
        using var mail = new MailMessage
        {
            From = new MailAddress(_options.FromAddress, _options.FromName),
            Subject = message.Subject,
            Body = message.Body
        };
        mail.To.Add(message.To);

        // SmtpClient is obsolete but adequate for a self-hosted relay; the transport is
        // pluggable (implement IEmailSender + flip Email:Sender) if a richer client is needed.
#pragma warning disable SYSLIB0014
        using var client = new SmtpClient(_options.Smtp.Host, _options.Smtp.Port) { EnableSsl = _options.Smtp.UseSsl };
#pragma warning restore SYSLIB0014
        if (!string.IsNullOrEmpty(_options.Smtp.Username))
        {
            client.Credentials = new NetworkCredential(_options.Smtp.Username, _options.Smtp.Password);
        }

        await client.SendMailAsync(mail, ct);
    }
}
