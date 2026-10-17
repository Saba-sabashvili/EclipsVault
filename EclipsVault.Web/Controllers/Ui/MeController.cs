using EclipsVault.Core.Domain.Enums;
using EclipsVault.Web.Authorization;
using EclipsVault.Web.Extensions;
using EclipsVault.Web.Middleware;
using EclipsVault.Web.Models.Ui;
using EclipsVault.Web.Services;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers.Ui;

/// <summary>
/// Who is signed in, for the Angular UI's first call. Part of the UI API: it accepts the session
/// cookie and nothing else, so an API key can never drive it (ADR-0005). It also hands Angular a
/// fresh antiforgery request token for its unsafe requests (ADR-0004).
/// </summary>
[ApiController]
[Route("api/ui/me")]
[Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme, Policy = VaultPolicies.Session)]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[Produces("application/json")]
public sealed class MeController(
    IAuthorizationService authorization,
    IAntiforgery antiforgery,
    LicenseNudgeState licenseNudge) : ControllerBase
{
    /// <summary>The cookie Angular's built-in XSRF support reads, by its default name.</summary>
    private const string XsrfCookie = "XSRF-TOKEN";

    [HttpGet]
    public async Task<ActionResult<MeResponse>> Get()
    {
        // A session missing the vault attribute claims is stale: refuse it rather than show a
        // clearance or project the server never issued, as the Legacy UI's My access does.
        var project = User.GetProject();
        if (User.GetClearanceOrNull() is not { } clearance || project.Length == 0)
        {
            return UiApiProblem.Unauthenticated();
        }

        var areas = new List<string>();
        foreach (var area in UiAreas.All)
        {
            if ((await authorization.AuthorizeAsync(User, HttpContext, area.Policy)).Succeeded)
            {
                areas.Add(area.Key);
            }
        }

        IssueXsrfToken();

        return new MeResponse(
            User.GetUsername(),
            User.GetDisplayName(),
            clearance.ToDisplayName(),
            project,
            areas,
            Url.Action("Avatar", "Profile", new { v = User.GetAvatarVersion() })!,
            areas.Contains(UiAreas.License) ? LicenseNoticeFor(licenseNudge) : null);
    }

    /// <summary>
    /// The request token only, readable by script so Angular can echo it in the header antiforgery
    /// accepts. On its own it is worthless: it must match the HttpOnly antiforgery cookie and this
    /// session's identity, which is why it is reissued here rather than once per sign-in.
    /// </summary>
    private void IssueXsrfToken()
    {
        var tokens = antiforgery.GetAndStoreTokens(HttpContext);
        Response.Cookies.Append(XsrfCookie, tokens.RequestToken!, new CookieOptions
        {
            HttpOnly = false,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/",
        });
    }

    /// <summary>The Legacy UI's licence banner, word for word, or null when it would not show.</summary>
    private static LicenseNotice? LicenseNoticeFor(LicenseNudgeState nudge)
    {
        if (!nudge.ShowBanner)
        {
            return null;
        }

        return nudge.Status != LicenseStatus.Valid
            ? new LicenseNotice(
                "Running unlicensed.",
                $"{nudge.Message} This changes nothing about how the vault runs — it only affects this notice.")
            : new LicenseNotice(
                "Premium features beyond your tier.",
                $"In use but not covered by your license: {string.Join(", ", nudge.PremiumFeaturesBeyondTier)}.");
    }
}
