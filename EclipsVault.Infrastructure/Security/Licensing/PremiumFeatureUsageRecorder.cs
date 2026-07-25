using System.Collections.Concurrent;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Core.Domain.Exceptions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Security.Licensing;

/// <summary>
/// Soft, deduplicated recorder for premium-feature use on an unlicensed/under-tier vault. If the
/// license already grants the feature it does nothing. Otherwise, once per feature per process, it
/// logs a warning and writes a single non-critical audit row. It never throws — a failed audit write
/// is swallowed — so it can sit on a hot path without ever affecting the operation.
/// </summary>
public sealed class PremiumFeatureUsageRecorder : IPremiumFeatureUsage
{
    private readonly ILicenseState _license;
    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<PremiumFeatureUsageRecorder> _logger;
    private readonly ConcurrentDictionary<string, byte> _recorded = new(StringComparer.Ordinal);

    public PremiumFeatureUsageRecorder(
        ILicenseState license,
        IServiceScopeFactory scopes,
        ILogger<PremiumFeatureUsageRecorder> logger)
    {
        _license = license;
        _scopes = scopes;
        _logger = logger;
    }

    public async Task RecordUseAsync(string featureKey, CancellationToken ct)
    {
        // Licensed for this feature — nothing to surface. The common, hot-path branch.
        if (_license.Allows(featureKey))
            return;

        // Already surfaced this feature this process — one line is enough, never spam the trail.
        if (!_recorded.TryAdd(featureKey, 0))
            return;

        _logger.LogWarning(
            "Premium feature '{Feature}' was used without a license entitlement. This does not restrict " +
            "the vault — it is a licensing reminder.", featureKey);

        try
        {
            // The sink is scoped; take a scope of our own since this recorder is a singleton.
            await using var scope = _scopes.CreateAsyncScope();
            var sink = scope.ServiceProvider.GetRequiredService<IAuditSink>();
            await sink.WriteAsync(
                new AuditEntry
                {
                    Action = AuditAction.LicenseFeatureUnlicensed,
                    ResourceType = "License",
                    ResourceName = featureKey,
                    Details = $"Premium feature '{featureKey}' exercised without a license entitlement.",
                    IsCritical = false,
                    ActorUsername = "system"
                },
                ct);
        }
        // Deliberately catch everything. The audit sink signals its own failure as
        // AuditWriteFailedException, but this also creates a scope and resolves a service — during
        // shutdown either can throw something else entirely (ObjectDisposedException, for one), and
        // that would travel up into the secret operation that called this. A licensing reminder must
        // never be able to affect an operation, which is the invariant the whole class exists for,
        // so the catch has to be as wide as the promise.
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Could not record the unlicensed-feature-use audit row for '{Feature}' — continuing " +
                "(licensing never blocks the vault).", featureKey);
        }
    }
}
