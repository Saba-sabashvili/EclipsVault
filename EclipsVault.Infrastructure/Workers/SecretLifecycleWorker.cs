using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Workers;

public sealed class LifecycleOptions
{
    public const string SectionName = "Lifecycle";

    /// <summary>Seconds between expiry sweeps.</summary>
    public int SweepIntervalSeconds { get; set; } = 60;
}

/// <summary>
/// Background reaper for expired secrets: wakes on a fixed interval, shreds key
/// material past its TTL (keeping an auditable tombstone), evicts stale cache
/// entries, and documents every shred. A failed sweep never kills the worker.
/// </summary>
public sealed class SecretLifecycleWorker : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly LifecycleOptions _options;
    private readonly TimeProvider _clock;
    private readonly ILogger<SecretLifecycleWorker> _logger;

    public SecretLifecycleWorker(
        IServiceScopeFactory scopeFactory,
        IOptions<LifecycleOptions> options,
        TimeProvider clock,
        ILogger<SecretLifecycleWorker> logger)
    {
        _scopeFactory = scopeFactory;
        _options = options.Value;
        _clock = clock;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Secret lifecycle worker started; sweep interval {SweepIntervalSeconds}s", _options.SweepIntervalSeconds);

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_options.SweepIntervalSeconds));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                try
                {
                    await SweepAsync(stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Secret lifecycle sweep failed; will retry on the next interval");
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Secret lifecycle worker stopping");
        }
    }

    private async Task SweepAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ISecretRepository>();
        var cache = scope.ServiceProvider.GetRequiredService<ISecretCache>();

        var now = _clock.GetUtcNow();
        var expired = await repository.ListExpiredAsync(now, ct);

        foreach (var secret in expired)
        {
            secret.Shred(now);
            await repository.ShredAsync(secret, ct); // purges archived versions + records SecretShredded atomically
            await cache.EvictAsync(secret.Id, ct);

            _logger.LogInformation(
                "Shredded expired secret {SecretId} ({SecretName}); TTL elapsed at {ExpiresAtUtc}",
                secret.Id, secret.Name, secret.ExpiresAtUtc);
        }
    }
}
