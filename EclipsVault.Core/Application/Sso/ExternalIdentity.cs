namespace EclipsVault.Core.Application.Sso;

/// <summary>
/// What an identity provider claims about whoever just authenticated to it. Everything here is the
/// IdP's assertion, not the vault's knowledge — which is the whole reason this is a separate type
/// from <c>UserDto</c>. Nothing in it may be trusted to grant anything until the vault has matched
/// it to an account of its own.
/// </summary>
/// <param name="Issuer">The <c>iss</c> claim — which IdP said this.</param>
/// <param name="Subject">The <c>sub</c> claim — the IdP's stable id for the person.</param>
/// <param name="Email">The <c>email</c> claim. The link to a vault account, and therefore the
/// attack surface: see <see cref="EmailVerified"/>.</param>
/// <param name="EmailVerified">The <c>email_verified</c> claim. Load-bearing, not informational —
/// an IdP that lets people self-assert an unverified address lets them self-assert
/// <c>someone-elses@vault.example</c>, and linking on that is account takeover.</param>
/// <param name="AuthenticationMethods">The <c>amr</c> claim (RFC 8176) — how the IdP says it
/// authenticated them. Absent unless the IdP is configured to send it, which is exactly why its
/// absence must mean "no factors asserted" rather than "probably fine".</param>
public sealed record ExternalIdentity(
    string? Issuer,
    string? Subject,
    string? Email,
    bool EmailVerified,
    IReadOnlyCollection<string> AuthenticationMethods);
