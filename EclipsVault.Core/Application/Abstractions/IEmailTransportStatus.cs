namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// How this deployment is currently configured to deliver notification email, described for an
/// operator reading the outbox page.
///
/// <para>
/// Deliberately narrower than the transport configuration it summarises: that carries the SMTP
/// username and password, and an admin screen showing where mail goes has no need of either. What
/// is exposed here is safe to render.
/// </para>
/// </summary>
public interface IEmailTransportStatus
{
    /// <summary>When false, notifications are recorded as suppressed and never dispatched.</summary>
    bool Enabled { get; }

    /// <summary>The configured transport — "Smtp", or "Log" for the development recorder.</summary>
    string Transport { get; }

    /// <summary><c>host:port</c> when the transport is SMTP; null otherwise. Never credentials.</summary>
    string? SmtpTarget { get; }
}
