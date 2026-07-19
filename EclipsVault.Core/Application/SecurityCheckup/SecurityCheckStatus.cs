namespace EclipsVault.Core.Application.SecurityCheckup;

/// <summary>
/// How a single control scored. Ordered by urgency so a numeric compare (used to rank the
/// list most-important-first) puts problems above passes.
/// </summary>
public enum SecurityCheckStatus
{
    /// <summary>The control is in place — nothing to do.</summary>
    Pass = 0,

    /// <summary>Not wrong, but the account would be stronger with it addressed.</summary>
    Recommended = 1,

    /// <summary>A real gap that meaningfully weakens the account — do this first.</summary>
    ActionNeeded = 2
}
