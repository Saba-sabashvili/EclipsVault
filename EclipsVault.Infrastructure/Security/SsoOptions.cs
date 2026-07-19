namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Wiring for the OpenID Connect provider. Off unless configured, so a deployment that does not use
/// SSO carries no SSO attack surface.
/// </summary>
public sealed class SsoOptions
{
    public const string SectionName = "Sso";

    public bool Enabled { get; init; }

    /// <summary>The IdP's issuer URL — discovery, JWKS and token validation all hang off it.</summary>
    public string Authority { get; init; } = string.Empty;

    public string ClientId { get; init; } = string.Empty;

    /// <summary>Belongs in the environment or a secret store, never in appsettings.json.</summary>
    public string ClientSecret { get; init; } = string.Empty;

    /// <summary>What the sign-in button says.</summary>
    public string DisplayName { get; init; } = "single sign-on";

    /// <summary>
    /// Whether an IdP that asserts multi-factor authentication satisfies this vault's second factor.
    /// False by default: see <c>SsoPolicy</c> for why that is not a shrug.
    /// </summary>
    public bool TrustIdpMultiFactor { get; init; }

    /// <summary>
    /// Allows plain HTTP to the IdP. Development only — a discovery document fetched over HTTP can
    /// be rewritten in flight, which means the keys used to validate every token can be too.
    /// </summary>
    public bool AllowInsecureHttp { get; init; }
}
