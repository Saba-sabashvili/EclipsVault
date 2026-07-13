
namespace EclipsVault.Web.Models;

public sealed class DashboardViewModel
{
    public string Username { get; init; } = string.Empty;

    public bool IsAdmin { get; init; }

    public int TotalActiveSecrets { get; init; }

    public int DevelopmentCount { get; init; }

    public int StagingCount { get; init; }

    public int ProductionCount { get; init; }

    public int ExpiringWithin7Days { get; init; }

    public int UserCount { get; init; }

    public int CriticalEventsLast24h { get; init; }

    public IReadOnlyList<AuditEntryDto> RecentEvents { get; init; } = [];

    public IReadOnlyList<ExpiringSecretDto> ExpiringSoon { get; init; } = [];
}
