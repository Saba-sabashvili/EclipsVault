using EclipsVault.Core.Domain.Entities;

namespace EclipsVault.Core.Application.Secrets;

/// <summary>
/// The one definition of "expiring soon". The dashboard banner, the "Expiring soon" panel, and the
/// lifecycle worker's expiry notices all read this, so what the vault warns you about on screen and
/// what it emails you about can never drift apart.
/// </summary>
public static class SecretExpiry
{
    /// <summary>How far ahead a secret counts as expiring soon.</summary>
    public const int SoonWindowDays = 7;

    /// <summary>The instant beyond which an expiry is not yet "soon".</summary>
    public static DateTimeOffset SoonCutoff(DateTimeOffset nowUtc) => nowUtc.AddDays(SoonWindowDays);

    /// <summary>True when the secret has a deadline that falls inside the warning window.</summary>
    public static bool IsExpiringSoon(Secret secret, DateTimeOffset nowUtc)
        => secret.ExpiresAtUtc is { } expiry && expiry <= SoonCutoff(nowUtc);

    /// <summary>
    /// True when an expiry notice is owed: the deadline is in the warning window and no notice has
    /// been sent for <i>this</i> deadline yet. Comparing against the deadline (rather than a
    /// "notified" flag) makes renewal self-healing — pushing the expiry out re-arms the notice
    /// without anyone having to remember to clear a flag.
    /// </summary>
    public static bool NeedsExpiryNotice(Secret secret, DateTimeOffset nowUtc)
        => !secret.IsShredded
           && IsExpiringSoon(secret, nowUtc)
           && secret.ExpiryNoticeSentForUtc != secret.ExpiresAtUtc;
}
