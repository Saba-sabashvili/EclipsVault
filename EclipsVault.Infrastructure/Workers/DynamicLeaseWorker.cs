using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Workers;

public sealed class DynamicLeaseOptions
{
    public const string SectionName = "DynamicSecrets";

    /// <summary>
    /// Seconds between reaping passes. This is the real precision of a lease: a credential can
    /// outlive its TTL by up to one interval, so it is deliberately tighter than the secret sweep.
    /// </summary>
    public int ReapIntervalSeconds { get; set; } = 30;
}

/// <summary>
/// Reaps dynamic credentials whose lease has elapsed — the half of leasing that makes the other
/// half safe. Without this, "short-lived credential" is just a promise on a web page.
///
/// It is deliberately separate from the secret lifecycle worker: reaping a lease reaches out to a
/// live external system and can fail in ways shredding a local row cannot, and it runs on its own
/// (tighter) interval. A failed pass never kills the worker; individual failures are recorded on
/// their lease as RevocationFailed and audited as critical, because that credential may still work.
/// </summary>
public sealed class DynamicLeaseWorker : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly DynamicLeaseOptions _options;
    private readonly ILogger<DynamicLeaseWorker> _logger;

    public DynamicLeaseWorker(
        IServiceScopeFactory scopeFactory,
        IOptions<DynamicLeaseOptions> options,
        ILogger<DynamicLeaseWorker> logger)
    {
        _scopeFactory = scopeFactory;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "Dynamic lease worker started; reap interval {ReapIntervalSeconds}s", _options.ReapIntervalSeconds);

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_options.ReapIntervalSeconds));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                try
                {
                    await ReapAsync(stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Dynamic lease reap failed; will retry on the next interval");
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Dynamic lease worker stopping");
        }
    }

    private async Task ReapAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<IDynamicSecretService>();

        var closed = await service.ReapDueLeasesAsync(ct);
        if (closed > 0)
        {
            _logger.LogInformation("Reaped {ClosedLeaseCount} elapsed dynamic credential lease(s)", closed);
        }
    }
}
