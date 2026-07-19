using System.Security.Claims;
using EclipsVault.Core.Application.Sso;

namespace EclipsVault.Web.Authentication;

/// <summary>
/// Reads what the identity provider asserted out of the OIDC principal, and nothing more.
///
/// The translation lives here rather than in Core because claim names are a protocol detail; Core
/// gets an <see cref="ExternalIdentity"/> and decides. Nothing is inferred on the way through — in
/// particular a missing <c>email_verified</c> reads as <c>false</c>, because "the IdP did not say"
/// and "the IdP said yes" must never collapse into the same value when the answer decides whether an
/// address may be matched to an account.
/// </summary>
public static class ExternalIdentityReader
{
    public static ExternalIdentity Read(ClaimsPrincipal principal)
    {
        var verified = principal.FindFirst("email_verified")?.Value;

        return new ExternalIdentity(
            Issuer: principal.FindFirst("iss")?.Value ?? principal.Identity?.AuthenticationType,
            Subject: principal.FindFirst("sub")?.Value,
            Email: principal.FindFirst("email")?.Value,
            EmailVerified: bool.TryParse(verified, out var isVerified) && isVerified,
            AuthenticationMethods: principal.FindAll("amr").Select(c => c.Value).ToArray());
    }
}
