using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Licensing;

/// <summary>Stable capability keys a license may grant. Kept as strings so a license can carry a
/// bespoke set without recompiling the verifier.</summary>
public static class LicenseFeatures
{
    public const string Sso = "sso";
    public const string Kms = "kms";
    public const string RedisHa = "redis-ha";
    public const string DynamicSecrets = "dynamic-secrets";
    public const string ManagedRotation = "managed-rotation";
    public const string AuditAttestation = "audit-attestation";
}

/// <summary>
/// Maps a tier to the features it grants, and resolves the <em>effective</em> feature set for a
/// license: the explicit <see cref="LicenseClaims.Features"/> if the vendor set any, otherwise the
/// tier default. Base secret management (local KEK, TOTP, passkeys, audit chain, ABAC) is never
/// listed here — it is the product and is never gated or nudged.
/// </summary>
public static class LicenseTierFeatures
{
    private static readonly string[] Pro =
        [LicenseFeatures.Sso, LicenseFeatures.Kms, LicenseFeatures.RedisHa, LicenseFeatures.DynamicSecrets];

    private static readonly string[] Enterprise =
        [.. Pro, LicenseFeatures.ManagedRotation, LicenseFeatures.AuditAttestation];

    public static IReadOnlyList<string> For(LicenseTier tier) => tier switch
    {
        LicenseTier.Pro => Pro,
        LicenseTier.Enterprise => Enterprise,
        _ => []
    };

    public static IReadOnlySet<string> Effective(LicenseClaims claims)
        => claims.Features.Count > 0
            ? new HashSet<string>(claims.Features, StringComparer.Ordinal)
            : new HashSet<string>(For(claims.Tier), StringComparer.Ordinal);
}
