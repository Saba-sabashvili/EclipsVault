using System.Net;
using Microsoft.Extensions.Options;

namespace EclipsVault.Web.Authorization;

/// <summary>
/// The environmental facts an ABAC decision depends on that are <i>not</i> subject attributes:
/// whether the caller's current network is trusted, and whether the production access window is
/// open right now. Computed once, here, so the enforcement path (<see cref="SecretAccessHandler"/>)
/// and the self-service "My access" explanation both read from a single source of truth — the
/// explanation can never drift from what is actually enforced.
/// </summary>
public sealed record AccessContext(
    IPAddress? SourceIp,
    bool IsTrustedNetwork,
    bool IsWithinProductionWindow,
    int WindowStartHour,
    int WindowEndHour,
    string WindowZoneLabel);

public interface IAccessContextProvider
{
    /// <summary>Snapshots the current request's network trust and the production window state.</summary>
    Task<AccessContext> CurrentAsync(CancellationToken ct);
}

public sealed class AccessContextProvider : IAccessContextProvider
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ITrustedNetworkService _trustedNetworks;
    private readonly AbacOptions _options;
    private readonly TimeZoneInfo? _windowZone;
    private readonly TimeProvider _clock;

    public AccessContextProvider(
        IHttpContextAccessor httpContextAccessor,
        ITrustedNetworkService trustedNetworks,
        IOptions<AbacOptions> options,
        TimeProvider clock,
        ILogger<AccessContextProvider> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _trustedNetworks = trustedNetworks;
        _options = options.Value;
        _clock = clock;
        _windowZone = ResolveWindowZone(_options.TimeZoneId, logger);
    }

    public async Task<AccessContext> CurrentAsync(CancellationToken ct)
    {
        var sourceIp = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress;

        // Static config ranges first (cheap), then the runtime-managed trusted networks.
        var isTrusted = NetworkRules.IsInAnyCidr(sourceIp, _options.TrustedIpCidrs);
        if (!isTrusted && sourceIp is not null)
        {
            isTrusted = await _trustedNetworks.IsTrustedAsync(sourceIp, ct);
        }

        return new AccessContext(
            sourceIp,
            isTrusted,
            IsWithinProductionWindow(_clock.GetUtcNow()),
            _options.ProductionWindowStartUtcHour,
            _options.ProductionWindowEndUtcHour,
            _windowZone?.Id ?? "UTC");
    }

    private bool IsWithinProductionWindow(DateTimeOffset nowUtc)
    {
        var hour = _windowZone is null
            ? nowUtc.UtcDateTime.Hour
            : TimeZoneInfo.ConvertTime(nowUtc, _windowZone).Hour;
        return hour >= _options.ProductionWindowStartUtcHour
               && hour < _options.ProductionWindowEndUtcHour;
    }

    private static TimeZoneInfo? ResolveWindowZone(string? timeZoneId, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(timeZoneId))
        {
            return null; // interpret the window in UTC (historical behaviour)
        }

        try
        {
            return TimeZoneInfo.FindSystemTimeZoneById(timeZoneId);
        }
        catch (Exception ex) when (ex is TimeZoneNotFoundException or InvalidTimeZoneException)
        {
            logger.LogWarning(ex, "Abac:TimeZoneId '{TimeZoneId}' could not be resolved; falling back to UTC for the production window", timeZoneId);
            return null;
        }
    }
}
