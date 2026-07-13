using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Notifications;

/// <summary>
/// Development transport: it "delivers" a message by writing a log line, so the flow works
/// end to end (and the outbox records it) without a mail server. The default in dev.
/// </summary>
public sealed class LoggingEmailSender : IEmailSender
{
    private readonly ILogger<LoggingEmailSender> _logger;

    public LoggingEmailSender(ILogger<LoggingEmailSender> logger) => _logger = logger;

    public string Transport => "Log";

    public Task SendAsync(EmailMessage message, CancellationToken ct)
    {
        _logger.LogInformation("Notification email (log transport) → {To}: {Subject}", message.To, message.Subject);
        return Task.CompletedTask;
    }
}
