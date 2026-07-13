namespace EclipsVault.Core.Application.Notifications;

/// <summary>
/// Composes and dispatches notification emails for domain events, recording each to the
/// outbox. Every method is fail-soft — a notification never breaks the triggering operation.
/// </summary>
public interface INotificationService
{
    Task NotifyAccessRequestDecidedAsync(
        Guid requesterUserId, string secretName, bool approved, string reviewer, string? note, CancellationToken ct);

    Task NotifyPasswordChangedAsync(Guid userId, CancellationToken ct);

    Task NotifyUserProvisionedAsync(string email, string displayName, string username, CancellationToken ct);

    /// <summary>The most recent outbox rows, newest first, for the admin Notifications page.</summary>
    Task<IReadOnlyList<EmailLogDto>> ListRecentAsync(int max, CancellationToken ct);
}
