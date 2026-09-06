using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Domain.Exceptions;

namespace EclipsVault.Tests.TestDoubles;

/// <summary>
/// Records which feature keys were reported used. Default-allow: <see cref="RequireAsync"/> permits
/// everything unless the feature is added to <see cref="Denied"/>, so existing tests are unaffected
/// and only the gate tests opt into a refusal.
/// </summary>
public sealed class RecordingPremiumFeatureUsage : IPremiumFeatureUsage
{
    public List<string> Recorded { get; } = [];

    /// <summary>Features to refuse from <see cref="RequireAsync"/>. Empty by default — everything is allowed.</summary>
    public HashSet<string> Denied { get; } = new(StringComparer.Ordinal);

    public Task RecordUseAsync(string featureKey, CancellationToken ct)
    {
        Recorded.Add(featureKey);
        return Task.CompletedTask;
    }

    public Task RequireAsync(string featureKey, CancellationToken ct)
    {
        Recorded.Add(featureKey);
        return Denied.Contains(featureKey)
            ? throw new PremiumFeatureNotLicensedException(featureKey)
            : Task.CompletedTask;
    }
}
