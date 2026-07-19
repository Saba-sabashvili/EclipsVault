namespace EclipsVault.Infrastructure.Security;

/// <summary>Budget for the authentication surface. Defaults match the limiter this replaced.</summary>
public sealed class AuthThrottleOptions
{
    public const string SectionName = "AuthThrottle";

    /// <summary>Requests allowed per window, per source address.</summary>
    public int PermitLimit { get; set; } = 11;

    /// <summary>Length of the fixed window, in seconds.</summary>
    public int WindowSeconds { get; set; } = 120;
}
