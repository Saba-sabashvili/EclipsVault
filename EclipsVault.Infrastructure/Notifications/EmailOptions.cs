namespace EclipsVault.Infrastructure.Notifications;

/// <summary>Email transport configuration (the <c>Email</c> section).</summary>
public sealed class EmailOptions
{
    public const string SectionName = "Email";

    /// <summary>Which transport to use: "Log" (dev — records + logs only) or "Smtp".</summary>
    public string Sender { get; set; } = "Log";

    /// <summary>When false, notifications are recorded as suppressed and never dispatched.</summary>
    public bool Enabled { get; set; } = true;

    public string FromAddress { get; set; } = "no-reply@eclipsvault.local";

    public string FromName { get; set; } = "EclipsVault";

    public SmtpOptions Smtp { get; set; } = new();
}

public sealed class SmtpOptions
{
    public string Host { get; set; } = "localhost";

    public int Port { get; set; } = 25;

    public bool UseSsl { get; set; }

    public string? Username { get; set; }

    public string? Password { get; set; }
}
