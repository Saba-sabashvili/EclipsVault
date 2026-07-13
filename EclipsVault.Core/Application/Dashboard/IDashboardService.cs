using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Dashboard;

/// <summary>A secret nearing its TTL, surfaced so it can be rotated before it is shredded.</summary>
public sealed record ExpiringSecretDto(Guid Id, string Name, SecretEnvironment Environment, DateTimeOffset ExpiresAtUtc);

public sealed record DashboardDto(
    int TotalActiveSecrets,
    int DevelopmentCount,
    int StagingCount,
    int ProductionCount,
    int ExpiringWithin7Days,
    int UserCount,
    int CriticalEventsLast24h,
    IReadOnlyList<AuditEntryDto> RecentEvents,
    IReadOnlyList<ExpiringSecretDto> ExpiringSoon);

/// <summary>Aggregates vault state for the overview page.</summary>
public interface IDashboardService
{
    /// <summary>Pass a username to restrict the activity feed to that actor (non-admin view).</summary>
    Task<DashboardDto> GetAsync(string? restrictActivityToUsername, CancellationToken ct);
}
