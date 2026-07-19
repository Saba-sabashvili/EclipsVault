using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Licensing;

/// <summary>
/// What a license asserts. The vendor mints this offline and signs it; the app verifies the
/// signature and reads these fields. <see cref="MaxNodes"/> is honor-based (shown, not enforced).
/// <see cref="Features"/> may be empty, in which case the tier's default feature set applies.
///
/// <para><see cref="NotAfterUtc"/> and <see cref="UpdatesUntilUtc"/> are deliberately separate. A Max
/// licence is <em>perpetual</em>: it grants its features forever, so <see cref="NotAfterUtc"/> is null
/// and the licence never verifies as expired. <see cref="UpdatesUntilUtc"/> is the update entitlement —
/// the date after which the customer is no longer entitled to new releases. It never disables a
/// feature or changes the licence status; a lapsed update window is a renewal nudge, not an outage.
/// A genuinely time-limited licence (an evaluation) is the one case that sets <see cref="NotAfterUtc"/>,
/// and there the features are meant to stop.</para>
/// </summary>
public sealed record LicenseClaims(
    string LicenseId,
    LicenseTier Tier,
    string IssuedTo,
    string? Contact,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset? NotAfterUtc,
    DateTimeOffset? UpdatesUntilUtc,
    int MaxNodes,
    IReadOnlyList<string> Features);
