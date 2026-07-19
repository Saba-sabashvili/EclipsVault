namespace EclipsVault.Core.Application.Sso;

/// <summary>
/// Turns an identity provider's assertion into the vault's own decision.
///
/// The IdP proves <em>who someone is</em>. This decides whether they may in, and whether they are
/// finished authenticating. Those stay the vault's questions on purpose: an IdP administrator who
/// could answer them would be able to read every secret here, and the trail would record it as
/// legitimate — correctly hashed, signed, offline-verifiable, and wrong.
/// </summary>
public interface ISsoSignInService
{
    Task<SsoSignInResult> SignInAsync(ExternalIdentity identity, CancellationToken ct);
}
