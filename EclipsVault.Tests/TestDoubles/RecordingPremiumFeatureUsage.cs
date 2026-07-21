using EclipsVault.Core.Application.Abstractions;

namespace EclipsVault.Tests.TestDoubles;

/// <summary>Records which feature keys were reported used; never changes behaviour.</summary>
public sealed class RecordingPremiumFeatureUsage : IPremiumFeatureUsage
{
    public List<string> Recorded { get; } = [];

    public Task RecordUseAsync(string featureKey, CancellationToken ct)
    {
        Recorded.Add(featureKey);
        return Task.CompletedTask;
    }
}
