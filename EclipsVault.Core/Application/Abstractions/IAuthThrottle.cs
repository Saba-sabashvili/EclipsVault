namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Damps the request rate on the authentication surface, partitioned by caller (source IP).
///
/// This is deliberately a port rather than the framework's built-in rate limiter: that one
/// partitions in memory, so N replicas would each grant the full budget and an attacker would get
/// N× the intended rate simply because the vault scaled out. Behind this interface the budget can
/// live in Redis and be shared by every node.
///
/// It damps the <i>rate</i> of guessing; per-account lockout (persisted, and so already shared)
/// is what bounds the <i>number</i> of guesses. The two are complementary.
/// </summary>
public interface IAuthThrottle
{
    /// <summary>
    /// Counts one attempt against <paramref name="partitionKey"/>'s budget and reports whether it
    /// is still within it. Every call consumes a permit, including the ones it refuses — so a
    /// caller that keeps hammering stays refused for the rest of the window.
    /// </summary>
    Task<bool> TryAcquireAsync(string partitionKey, CancellationToken ct);
}
