namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// Records when a Licensed Capability was first exercised on this vault, which starts the evaluation
/// period the licence grants (30 consecutive days of production use, no licence key required).
/// One row per capability: the licence grants the period to assess <em>each</em> capability, so a
/// vault that first reaches for managed rotation a year after dynamic secrets still gets its full
/// window for it.
/// </summary>
/// <remarks>
/// The row lives in the operator's own database and deleting it restarts the clock. That is
/// deliberate: enforcement is soft, and circumvention requiring database or source edits is the
/// practical ceiling for source-available software. Do not add tamper-proofing here.
/// </remarks>
public class FeatureEvaluation
{
    /// <summary>The capability being evaluated — a <c>LicenseFeatures</c> constant, and the key.</summary>
    public string FeatureKey { get; set; } = string.Empty;

    /// <summary>When the capability was first exercised, which is when the window opened.</summary>
    public DateTimeOffset StartedAtUtc { get; set; }
}
