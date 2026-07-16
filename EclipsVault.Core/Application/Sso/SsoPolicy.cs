namespace EclipsVault.Core.Application.Sso;

/// <summary>
/// How much of the identity provider's word the vault takes.
/// </summary>
/// <param name="TrustIdpMultiFactor">
/// When true, an IdP that asserts it performed multi-factor authentication (via <c>amr</c>) satisfies
/// the vault's second factor, and the user goes straight to a session. When false — the default —
/// the vault asks for its own TOTP regardless of what the IdP did.
///
/// <para>Defaulting to false is deliberate. Trusting the IdP's factor is a legitimate choice, and the
/// normal one for enterprise SSO, but it hands the strength of every account here to a system this
/// vault does not administer. That should be something an operator turns on knowingly, not something
/// they inherit from a default they never read.</para>
/// </param>
public sealed record SsoPolicy(bool TrustIdpMultiFactor)
{
    public static readonly SsoPolicy Default = new(TrustIdpMultiFactor: false);
}
