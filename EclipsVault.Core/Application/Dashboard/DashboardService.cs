using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Dashboard;

/// <summary>Composes repository data into the overview snapshot. Pure aggregation, no I/O of its own.</summary>
public sealed class DashboardService : IDashboardService
{
    private const int RecentEventCount = 10;
    private const int ExpirySoonDays = 7;
    private const int ExpiringListLimit = 8;

    private readonly ISecretRepository _secrets;
    private readonly IUserRepository _users;
    private readonly IAuditLogReader _audit;
    private readonly TimeProvider _clock;

    public DashboardService(ISecretRepository secrets, IUserRepository users, IAuditLogReader audit, TimeProvider clock)
    {
        _secrets = secrets;
        _users = users;
        _audit = audit;
        _clock = clock;
    }

    public async Task<DashboardDto> GetAsync(string? restrictActivityToUsername, CancellationToken ct)
    {
        var now = _clock.GetUtcNow();

        var secrets = await _secrets.ListActiveAsync(now, ct);
        var users = await _users.ListAsync(ct);
        var recent = await _audit.ListRecentAsync(RecentEventCount, restrictActivityToUsername, ct);
        var criticalLast24h = await _audit.CountCriticalSinceAsync(now.AddHours(-24), ct);

        var expiryCutoff = now.AddDays(ExpirySoonDays);
        var expiringSoon = secrets
            .Where(s => s.ExpiresAtUtc is { } e && e <= expiryCutoff)
            .OrderBy(s => s.ExpiresAtUtc)
            .Take(ExpiringListLimit)
            .Select(s => new ExpiringSecretDto(s.Id, s.Name, s.Environment, s.ExpiresAtUtc!.Value))
            .ToList();

        return new DashboardDto(
            TotalActiveSecrets: secrets.Count,
            DevelopmentCount: secrets.Count(s => s.Environment == SecretEnvironment.Development),
            StagingCount: secrets.Count(s => s.Environment == SecretEnvironment.Staging),
            ProductionCount: secrets.Count(s => s.Environment == SecretEnvironment.Production),
            ExpiringWithin7Days: secrets.Count(s => s.ExpiresAtUtc is { } e && e <= expiryCutoff),
            UserCount: users.Count,
            CriticalEventsLast24h: criticalLast24h,
            RecentEvents: recent,
            ExpiringSoon: expiringSoon);
    }
}
