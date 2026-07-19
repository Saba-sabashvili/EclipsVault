namespace EclipsVault.Core.Domain.Enums;

/// <summary>
/// The commercial tier a license grants. Community is the free tier; Max unlocks every paid feature.
/// Two tiers by design — the product is sold as Community (free, limited) or Max (everything), so
/// there is no middle tier to reason about.
/// </summary>
public enum LicenseTier
{
    Community = 0,
    Max = 1
}
