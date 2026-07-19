using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Licensing;

/// <summary>
/// What a license asserts. The vendor mints this offline and signs it; the app verifies the
/// signature and reads these fields. <see cref="MaxNodes"/> is honor-based (shown, not enforced).
/// <see cref="Features"/> may be empty, in which case the tier's default feature set applies.
/// </summary>
public sealed record LicenseClaims(
    string LicenseId,
    LicenseTier Tier,
    string IssuedTo,
    string? Contact,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset? NotAfterUtc,
    int MaxNodes,
    IReadOnlyList<string> Features);
