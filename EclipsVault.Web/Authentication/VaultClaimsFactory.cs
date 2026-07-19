using System.Security.Claims;
using EclipsVault.Web.Authorization;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace EclipsVault.Web.Authentication;

/// <summary>
/// The single builder for the claim sets a sign-in issues. Both the short-lived pending-MFA
/// principal and the full interactive-session principal are minted here, so the exact claims a
/// session carries — the security-critical part — live in one auditable place instead of being
/// hand-assembled at each call site where they could silently drift apart. The read side lives in
/// <see cref="EclipsVault.Web.Extensions.ClaimsPrincipalExtensions"/>.
/// </summary>
public static class VaultClaimsFactory
{
    /// <summary>
    /// The principal issued after the password factor but before TOTP: it carries only enough
    /// identity to complete the second factor, under the short-lived pending-MFA scheme.
    /// </summary>
    public static ClaimsPrincipal CreatePendingMfaPrincipal(UserDto user) =>
        new(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username)
            ],
            AuthSchemes.MfaPending));

    /// <summary>
    /// The full interactive-session principal granted once both factors pass. It carries the ABAC
    /// attribute claims (clearance, project), the display/avatar hints the UI reads, the strong-auth
    /// timestamp, and a per-session id so a single device can be revoked on its own.
    /// </summary>
    public static ClaimsPrincipal CreateSessionPrincipal(UserDto user, Guid sessionId, DateTimeOffset authTime) =>
        new(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(VaultClaimTypes.Display, string.IsNullOrWhiteSpace(user.DisplayName) ? user.Username : user.DisplayName),
                new Claim(VaultClaimTypes.AvatarVersion, DateTimeOffset.UtcNow.Ticks.ToString()),
                new Claim(VaultClaimTypes.Clearance, ((int)user.Clearance).ToString()),
                new Claim(VaultClaimTypes.Project, user.ProjectKey),
                new Claim(VaultClaimTypes.AuthTime, authTime.ToUnixTimeSeconds().ToString()),
                new Claim(VaultClaimTypes.SessionId, sessionId.ToString())
            ],
            CookieAuthenticationDefaults.AuthenticationScheme));
}
