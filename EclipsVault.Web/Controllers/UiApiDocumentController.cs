using EclipsVault.Web.Hosting;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

/// <summary>The UI API contract is available to signed-in developers only (ADR-0007).</summary>
[Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
[ApiExplorerSettings(IgnoreApi = true)]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class UiApiDocumentController(IWebHostEnvironment environment) : ControllerBase
{
    [HttpGet("/openapi/ui.json")]
    public async Task<IActionResult> Get(CancellationToken cancellationToken)
    {
        if (!environment.IsDevelopment())
        {
            return NotFound();
        }

        return Content(await UiApiOpenApi.GenerateAsync(cancellationToken), "application/json");
    }
}
