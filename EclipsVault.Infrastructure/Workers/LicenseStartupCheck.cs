using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Core.Domain.Exceptions;
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
    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<LicenseStartupCheck> _logger;

    public LicenseStartupCheck(
        ILicenseState license,
        IHostEnvironment environment,
        IServiceScopeFactory scopes,
        ILogger<LicenseStartupCheck> logger)
    {
        _license = license;
        _environment = environment;
        _scopes = scopes;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("License check: {Status} — {Message}", _license.Status, _license.Message);

        // Development runs unlicensed by design (no pinned key), so it is never nagged or recorded.
        if (_environment.IsDevelopment() || _license.Status == LicenseStatus.Valid)
            return;

        _logger.LogWarning(
            "EclipsVault is running without a valid license ({Status}). This does not restrict the vault — " +
            "it is a licensing reminder.", _license.Status);

        try
        {
            // The sink is scoped; take a scope of our own since a hosted service is a singleton.
            await using var scope = _scopes.CreateAsyncScope();
            var sink = scope.ServiceProvider.GetRequiredService<IAuditSink>();
            await sink.WriteAsync(
                new AuditEntry
                {
                    Action = AuditAction.LicenseInvalidProductionUse,
                    ResourceType = "License",
                    ResourceName = _license.Status.ToString(),
                    Details = _license.Message,
                    // Not critical: IsCritical flags genuine security incidents (honey-token, revocation
                    // failure). A licensing reminder must never masquerade as one of those.
                    IsCritical = false,
                    ActorUsername = "system"
                },
                cancellationToken);
        }
        catch (AuditWriteFailedException ex)
        {
            _logger.LogWarning(ex,
                "Could not record the unlicensed-startup audit row — continuing (licensing never blocks the vault).");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
