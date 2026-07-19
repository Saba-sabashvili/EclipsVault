namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// The key one caller's budget is counted under, for one fixed window.
///
/// Deriving the window from the clock rather than from a stored start time is what lets replicas
/// agree without coordinating: every node computes the same bucket for the same instant, so the
/// in-memory and Redis throttles partition identically and a shared counter needs no leader.
/// </summary>
public static class AuthThrottleWindow
{
    public static string KeyFor(string partitionKey, DateTimeOffset nowUtc, int windowSeconds)
        => $"auth-throttle:{partitionKey}:{nowUtc.ToUnixTimeSeconds() / Math.Max(1, windowSeconds)}";
}
