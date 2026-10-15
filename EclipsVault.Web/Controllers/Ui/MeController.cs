using EclipsVault.Web.Extensions;
using EclipsVault.Web.Models.Ui;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers.Ui;

/// <summary>
/// Who is signed in, for the Angular UI's first call. Part of the UI API: it accepts the session
/// cookie and nothing else, so an API key can never drive it (ADR-0005).
/// </summary>
[ApiController]
[Route("api/ui/me")]
[Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[Produces("application/json")]
public sealed class MeController : ControllerBase
{
    [HttpGet]
    public ActionResult<MeResponse> Get()
    {
        // A session missing the vault attribute claims is stale: refuse it rather than show a
        // clearance or project the server never issued, as the Legacy UI's My access does.
        var project = User.GetProject();
        if (User.GetClearanceOrNull() is not { } clearance || project.Length == 0)
        {
            return Unauthorized();
        }

        return new MeResponse(User.GetUsername(), User.GetDisplayName(), clearance.ToDisplayName(), project);
    }
}
