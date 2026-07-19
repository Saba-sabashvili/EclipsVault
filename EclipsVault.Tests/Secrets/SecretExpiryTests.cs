using EclipsVault.Core.Application.Secrets;
using EclipsVault.Core.Domain.Entities;
using Xunit;

namespace EclipsVault.Tests.Secrets;

/// <summary>
/// The expiry-notice rule runs on every lifecycle sweep (once a minute), so "warn exactly once per
/// deadline" is the whole contract: warn too often and the owner gets a mail a minute for a week;
/// warn too rarely and their credential is shredded without notice. These pin both edges, plus the
/// re-arm on renewal that makes the marker self-healing.
/// </summary>
public class SecretExpiryTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 16, 12, 0, 0, TimeSpan.Zero);

    private static Secret Secret(DateTimeOffset? expiresAt, DateTimeOffset? noticeSentFor = null, bool shredded = false)
        => new()
        {
            Id = Guid.NewGuid(),
            Name = "prod/api-key",
            ExpiresAtUtc = expiresAt,
            ExpiryNoticeSentForUtc = noticeSentFor,
            IsShredded = shredded
        };

    [Fact]
    public void A_deadline_inside_the_window_is_expiring_soon()
        => Assert.True(SecretExpiry.IsExpiringSoon(Secret(Now.AddDays(3)), Now));

    [Fact]
    public void A_deadline_beyond_the_window_is_not_expiring_soon()
        => Assert.False(SecretExpiry.IsExpiringSoon(Secret(Now.AddDays(SecretExpiry.SoonWindowDays + 1)), Now));

    [Fact]
    public void A_secret_with_no_deadline_is_never_expiring_soon()
        => Assert.False(SecretExpiry.IsExpiringSoon(Secret(null), Now));

    [Fact]
    public void A_notice_is_owed_when_the_deadline_enters_the_window()
        => Assert.True(SecretExpiry.NeedsExpiryNotice(Secret(Now.AddDays(3)), Now));

    [Fact]
    public void A_notice_is_not_owed_twice_for_the_same_deadline()
    {
        // The idempotency guard: this is what stops a sweep-a-minute from mailing every minute.
        var expiry = Now.AddDays(3);
        Assert.False(SecretExpiry.NeedsExpiryNotice(Secret(expiry, noticeSentFor: expiry), Now));
    }

    [Fact]
    public void Renewing_re_arms_the_notice_without_clearing_any_flag()
    {
        // Warned about the old deadline, then rotated with a renewal that pushed it out. The new
        // deadline is its own event — when it comes back into the window, it is owed a fresh notice.
        var warnedFor = Now.AddDays(3);
        var renewed = Secret(Now.AddDays(5), noticeSentFor: warnedFor);

        Assert.True(SecretExpiry.NeedsExpiryNotice(renewed, Now));
    }

    [Fact]
    public void A_notice_is_not_owed_for_a_deadline_beyond_the_window()
        => Assert.False(SecretExpiry.NeedsExpiryNotice(Secret(Now.AddDays(SecretExpiry.SoonWindowDays + 1)), Now));

    [Fact]
    public void A_notice_is_not_owed_for_a_secret_with_no_deadline()
        => Assert.False(SecretExpiry.NeedsExpiryNotice(Secret(null), Now));

    [Fact]
    public void A_shredded_secret_is_never_owed_a_notice()
    {
        // Its key material is already gone — warning that it is about to expire would be nonsense.
        Assert.False(SecretExpiry.NeedsExpiryNotice(Secret(Now.AddDays(1), shredded: true), Now));
    }

    [Fact]
    public void The_window_boundary_is_inclusive()
        => Assert.True(SecretExpiry.IsExpiringSoon(Secret(SecretExpiry.SoonCutoff(Now)), Now));
}
