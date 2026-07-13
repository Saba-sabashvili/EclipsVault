using EclipsVault.Core.Domain.Entities;

namespace EclipsVault.Core.Application.Notifications;

/// <summary>Persistence port for the notification outbox.</summary>
public interface IEmailLogRepository
{
    Task AddAsync(EmailLog entry, CancellationToken ct);

    Task<IReadOnlyList<EmailLog>> ListRecentAsync(int max, CancellationToken ct);
}
