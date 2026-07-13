namespace EclipsVault.Core.Application.Authentication;

/// <summary>
/// Brute-force lockout thresholds. After <see cref="MaxFailedAttempts"/> consecutive
/// failed authentication attempts (password or TOTP), the account is locked for
/// <see cref="LockoutDuration"/>. A successful sign-in resets the counter.
/// </summary>
public sealed record LockoutPolicy(int MaxFailedAttempts, TimeSpan LockoutDuration)
{
    public static readonly LockoutPolicy Default = new(5, TimeSpan.FromMinutes(15));
}
