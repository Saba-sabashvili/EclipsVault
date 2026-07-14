namespace EclipsVault.Core.Application.Activity;

/// <summary>Read-only, actor-scoped projection of the audit trail into a personal activity feed.</summary>
public interface IActivityService
{
    /// <summary>
    /// The signed-in user's own activity, newest first, one page at a time. Scoped strictly to
    /// rows the user themselves generated (by user id), so it never discloses anyone else's actions.
    /// </summary>
    Task<ActivityFeed> GetForUserAsync(Guid userId, int page, int pageSize, CancellationToken ct);
}
