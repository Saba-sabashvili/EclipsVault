using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Core.Domain.Exceptions;
using EclipsVault.Infrastructure.Security.Licensing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Workers;

/// <summary>
/// Announces the resolved license once, at startup: logs its status, and — only outside Development
/// and only when the license is not Valid — records a single soft audit row so an operator has a
/// dated marker that the vault came up unlicensed.
///
/// It runs as a hosted service, not inline after <c>app.Build()</c>, for one concrete reason: the
/// audit sink is fail-closed and only completes once <see cref="Persistence.AuditGroupCommitter"/>
/// has drained the row, and that committer is itself a hosted service that starts with the host.
/// Writing through the sink before the committer is draining would enqueue a row nothing commits and
/// wait on it forever. Registered after the committer, this runs once the drain is live.
///
/// Licensing never blocks the vault: a failed audit write is logged and swallowed.
/// </summary>
public sealed class LicenseStartupCheck : IHostedService
{
    private readonly ILicenseState _license;
    private readonly IHostEnvironment _environment;
    private readonly ConfiguredPremiumFeatures _premiumFeatures;
    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<LicenseStartupCheck> _logger;

    public LicenseStartupCheck(
        ILicenseState license,
        IHostEnvironment environment,
        ConfiguredPremiumFeatures premiumFeatures,
        IServiceScopeFactory scopes,
        ILogger<LicenseStartupCheck> logger)
    {
        _license = license;
        _environment = environment;
        _premiumFeatures = premiumFeatures;
        _scopes = scopes;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("License check: {Status} — {Message}", _license.Status, _license.Message);

        // Development runs unlicensed by design (no pinned key), so it is never nagged or recorded.
        if (_environment.IsDevelopment())
            return;

        if (_license.Status != LicenseStatus.Valid)
        {
            _logger.LogWarning(
                "EclipsVault is running without a valid license ({Status}). This does not restrict the vault — " +
                "it is a licensing reminder.", _license.Status);

            await WriteSoftRowAsync(
                AuditAction.LicenseInvalidProductionUse,
                _license.Status.ToString(),
                _license.Message,
                cancellationToken);
            return;
        }

        // A valid license can still be a lower tier than the features switched on (e.g. Community with
        // Redis HA). Surface exactly which config-active features it does not grant.
        var beyondTier = _premiumFeatures.Active.Where(feature => !_license.Allows(feature)).ToArray();
        if (beyondTier.Length == 0)
            return;

        var features = string.Join(", ", beyondTier);
        _logger.LogWarning(
            "EclipsVault has premium features active that the current license does not grant: {Features}. " +
            "This does not restrict the vault — it is a licensing reminder.", features);

        await WriteSoftRowAsync(
            AuditAction.LicenseFeatureUnlicensed,
            features,
            $"Config-active premium features beyond the current license: {features}.",
            cancellationToken);
    }

    private async Task WriteSoftRowAsync(AuditAction action, string resourceName, string details, CancellationToken ct)
    {
        try
        {
            // The sink is scoped; take a scope of our own since a hosted service is a singleton.
            await using var scope = _scopes.CreateAsyncScope();
            var sink = scope.ServiceProvider.GetRequiredService<IAuditSink>();
            await sink.WriteAsync(
                new AuditEntry
                {
                    Action = action,
                    ResourceType = "License",
                    ResourceName = resourceName,
                    Details = details,
                    // A licensing reminder must never masquerade as a genuine security incident.
                    IsCritical = false,
                    ActorUsername = "system"
                },
                ct);
        }
        catch (AuditWriteFailedException ex)
        {
            _logger.LogWarning(ex,
                "Could not record the licensing audit row — continuing (licensing never blocks the vault).");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
