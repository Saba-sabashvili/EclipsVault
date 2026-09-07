using System.Collections.Concurrent;
using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Core.Domain.Exceptions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Security.Licensing;

/// <summary>
/// Soft, deduplicated recorder for premium-feature use on an unlicensed/under-tier vault. If the
/// license already grants the feature it does nothing. Otherwise, once per feature per process, it
/// logs a warning and writes a single non-critical audit row. <see cref="RecordUseAsync"/> never
/// throws — a failed audit write is swallowed — so it can sit on a hot path without ever affecting
/// the operation.
///
/// <see cref="RequireAsync"/> additionally enforces the gated capabilities, but only once the
/// evaluation period the licence grants has run out. Until then the capability is allowed and the
/// window is opened on first use, which is what keeps the binary consistent with LICENSE section 2
/// ("up to 30 consecutive days of Production Use", no licence key required).
/// </summary>
public sealed class PremiumFeatureUsageRecorder : IPremiumFeatureUsage
{
    private readonly ILicenseState _license;
    private readonly IEvaluationWindowStore _windows;
    private readonly TimeProvider _time;
    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<PremiumFeatureUsageRecorder> _logger;

    // Keyed by action as well as feature: a gated feature writes an evaluation-started row first and
    // a blocked row up to 30 days later, and keying on the feature alone would swallow the second.
    private readonly ConcurrentDictionary<(AuditAction, string), byte> _recorded = new();

    // A window's start never changes once set, so it is cached after the first lookup and the gate
    // stops touching the database. A deleted row is picked up on the next restart, which is the
    // right direction: it reopens the window rather than closing one early.
    private readonly ConcurrentDictionary<string, DateTimeOffset> _windowStarts = new(StringComparer.Ordinal);

    public PremiumFeatureUsageRecorder(
        ILicenseState license,
        IEvaluationWindowStore windows,
        TimeProvider time,
        IServiceScopeFactory scopes,
        ILogger<PremiumFeatureUsageRecorder> logger)
    {
        _license = license;
        _windows = windows;
        _time = time;
        _scopes = scopes;
        _logger = logger;
    }

    public async Task RecordUseAsync(string featureKey, CancellationToken ct)
    {
        // Licensed for this feature — nothing to surface. The common, hot-path branch.
        if (_license.Allows(featureKey))
            return;

        await RecordUnlicensedAsync(featureKey, AuditAction.LicenseFeatureUnlicensed, ct);
    }

    public async Task RequireAsync(string featureKey, CancellationToken ct)
    {
        // Licensed — the gate is transparent.
        if (_license.Allows(featureKey))
            return;

        if (!LicenseFeatures.Gated.Contains(featureKey))
        {
            await RecordUnlicensedAsync(featureKey, AuditAction.LicenseFeatureUnlicensed, ct);
            return;
        }

        // The licence grants an evaluation period for each Licensed Capability, with no key required.
        // A null start means the window could not be resolved at all, and licensing never decides an
        // operation on a storage failure — allow it.
        var startedAt = await ResolveWindowStartAsync(featureKey, ct);
        if (startedAt is null || EvaluationWindow.IsActive(startedAt.Value, _time.GetUtcNow()))
            return;

        await RecordUnlicensedAsync(featureKey, AuditAction.LicenseFeatureBlocked, ct);

        // The audit row is deduplicated, but the refusal is not: every call is refused.
        throw new PremiumFeatureNotLicensedException(featureKey);
    }

    /// <summary>
    /// When this capability's evaluation window opened, opening it now if this is its first use.
    /// Returns null when the store could not answer, which the caller treats as "allow".
    /// </summary>
    private async Task<DateTimeOffset?> ResolveWindowStartAsync(string featureKey, CancellationToken ct)
    {
        if (_windowStarts.TryGetValue(featureKey, out var cached))
            return cached;

        try
        {
            var window = await _windows.GetOrStartAsync(featureKey, ct);
            _windowStarts[featureKey] = window.StartedAtUtc;

            if (window.StartedNow)
            {
                _logger.LogInformation(
                    "Premium feature '{Feature}' was used for the first time without a licence. Its "
                    + "{Days}-day evaluation period is now open and ends {EndsAt:u}.",
                    featureKey, EvaluationWindow.Days, EvaluationWindow.EndsAt(window.StartedAtUtc));

                await WriteAuditAsync(
                    featureKey,
                    AuditAction.LicenseEvaluationStarted,
                    $"Evaluation of '{featureKey}' started — {EvaluationWindow.Days} days, ending "
                    + $"{EvaluationWindow.EndsAt(window.StartedAtUtc):u}.",
                    ct);
            }

            return window.StartedAtUtc;
        }
        // Deliberately catch everything. A licensing lookup that cannot reach the database must never
        // become the operator's outage, so an unresolvable window grants the capability rather than
        // refusing it. The direction of this failure is the whole point.
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Could not resolve the evaluation window for '{Feature}' — allowing the operation "
                + "(licensing never blocks the vault).", featureKey);
            return null;
        }
    }

    private async Task RecordUnlicensedAsync(string featureKey, AuditAction action, CancellationToken ct)
    {
        // Already surfaced this feature this process — one line is enough, never spam the trail.
        if (!_recorded.TryAdd((action, featureKey), 0))
            return;

        var blocked = action == AuditAction.LicenseFeatureBlocked;

        _logger.LogWarning(
            blocked
                ? "Premium feature '{Feature}' was refused: its evaluation period has ended and there "
                  + "is no license entitlement. Existing state is unaffected."
                : "Premium feature '{Feature}' was used without a license entitlement. This does not "
                  + "restrict the vault — it is a licensing reminder.",
            featureKey);

        await WriteAuditAsync(
            featureKey,
            action,
            blocked
                ? $"Premium feature '{featureKey}' refused — evaluation period ended, not licensed."
                : $"Premium feature '{featureKey}' exercised without a license entitlement.",
            ct);
    }

    private async Task WriteAuditAsync(string featureKey, AuditAction action, string details, CancellationToken ct)
    {
        try
        {
            // The sink is scoped; take a scope of our own since this recorder is a singleton.
            await using var scope = _scopes.CreateAsyncScope();
            var sink = scope.ServiceProvider.GetRequiredService<IAuditSink>();
            await sink.WriteAsync(
                new AuditEntry
                {
                    Action = action,
                    ResourceType = "License",
                    ResourceName = featureKey,
                    Details = details,
                    IsCritical = false,
                    ActorUsername = "system"
                },
                ct);
        }
        // Deliberately catch everything. The audit sink signals its own failure as
        // AuditWriteFailedException, but this also creates a scope and resolves a service — during
        // shutdown either can throw something else entirely (ObjectDisposedException, for one), and
        // that would travel up into the secret operation that called this. A licensing reminder must
        // never be able to affect an operation beyond the deliberate gated refusal, so the catch has
        // to be as wide as the promise.
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Could not record the premium-feature audit row for '{Feature}' — continuing " +
                "(licensing never blocks the vault).", featureKey);
        }
    }
}
