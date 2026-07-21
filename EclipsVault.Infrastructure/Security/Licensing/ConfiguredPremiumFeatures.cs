using EclipsVault.Core.Application.Licensing;
using EclipsVault.Infrastructure.Distributed;
using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Security.Licensing;

/// <summary>
/// The premium (Max-only) features switched on by this deployment's configuration — the three chosen
/// at startup: the external KMS engine, Redis-backed HA, and SSO. Computed once from the bound options
/// so there is a single source of truth (the banner and the startup license check both read it), and
/// it can never drift from how each feature is actually selected.
/// </summary>
public sealed class ConfiguredPremiumFeatures
{
    public ConfiguredPremiumFeatures(
        IOptions<CryptoOptions> crypto,
        IOptions<RedisOptions> redis,
        IOptions<SsoOptions> sso)
    {
        var active = new HashSet<string>(StringComparer.Ordinal);

        if (string.Equals(crypto.Value.Engine, VaultTransitCryptoEngine.EngineName, StringComparison.Ordinal))
            active.Add(LicenseFeatures.Kms);

        if (redis.Value.Enabled)
            active.Add(LicenseFeatures.RedisHa);

        if (!string.IsNullOrWhiteSpace(sso.Value.Authority))
            active.Add(LicenseFeatures.Sso);

        Active = active;
    }

    /// <summary>The config-activated premium feature keys (<see cref="LicenseFeatures"/> constants).</summary>
    public IReadOnlySet<string> Active { get; }
}
