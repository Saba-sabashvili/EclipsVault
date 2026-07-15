using System.Security.Claims;
using EclipsVault.Web.Authorization;

namespace EclipsVault.Web.Extensions;

/// <summary>
/// The single source of truth for reading the claims EclipsVault stamps onto a signed-in
/// principal. Parsing these by hand was duplicated across nearly every controller, the
/// authorization handlers, and the audit context; centralising it keeps the claim names — and,
/// crucially, their fail-closed defaults — in one reviewed place. The write side lives in
/// <see cref="EclipsVault.Web.Authentication.VaultClaimsFactory"/>.
/// </summary>
public static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// The signed-in user's id, or <see cref="Guid.Empty"/> when absent. Empty is the fail-closed
    /// default: it scopes a self-service read to no rows rather than risking another user's data.
    /// </summary>
    public static Guid GetUserId(this ClaimsPrincipal principal)
        => principal.GetUserIdOrNull() ?? Guid.Empty;

    /// <summary>
    /// The signed-in user's id, or null when absent — for flows that must branch on presence, such
    /// as the pending-MFA stage that runs before the full session identity exists.
    /// </summary>
    public static Guid? GetUserIdOrNull(this ClaimsPrincipal principal)
        => Guid.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null;

    /// <summary>The immutable login username (the audit anchor), or empty when unauthenticated.</summary>
    public static string GetUsername(this ClaimsPrincipal principal)
        => principal.Identity?.Name ?? string.Empty;

    /// <summary>This device's session id, or null when the principal carries none (e.g. an API-key caller).</summary>
    public static Guid? GetSessionId(this ClaimsPrincipal principal)
        => Guid.TryParse(principal.FindFirstValue(VaultClaimTypes.SessionId), out var id) ? id : null;

    /// <summary>The project the principal is scoped to, or empty when none is present.</summary>
    public static string GetProject(this ClaimsPrincipal principal)
        => principal.FindFirstValue(VaultClaimTypes.Project) ?? string.Empty;
}
