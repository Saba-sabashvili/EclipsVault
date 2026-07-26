using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Notifications;

/// <summary>
/// Adapts <see cref="EmailOptions"/> to <see cref="IEmailTransportStatus"/>. The SMTP target is
/// composed here rather than in a view, because deciding what "where does mail go" means for a given
/// transport is knowledge about the transport, not about how to display it — and because composing
/// it here is what keeps <see cref="SmtpOptions.Password"/> out of the presentation layer entirely.
/// </summary>
public sealed class EmailTransportStatus : IEmailTransportStatus
{
    private const string SmtpTransport = "Smtp";

    private readonly IOptions<EmailOptions> _options;

    public EmailTransportStatus(IOptions<EmailOptions> options) => _options = options;

    public bool Enabled => _options.Value.Enabled;

    public string Transport => _options.Value.Sender;

    public string? SmtpTarget
    {
        get
        {
            var email = _options.Value;
            return string.Equals(email.Sender, SmtpTransport, StringComparison.OrdinalIgnoreCase)
                ? $"{email.Smtp.Host}:{email.Smtp.Port}"
                : null;
        }
    }
}
