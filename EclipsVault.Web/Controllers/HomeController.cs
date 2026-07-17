using System.Diagnostics;
using EclipsVault.Web.Authorization;
using EclipsVault.Web.Extensions;
using EclipsVault.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

public sealed class HomeController : Controller
{
    private readonly IDashboardService _dashboard;

    public HomeController(IDashboardService dashboard) => _dashboard = dashboard;

    [AllowAnonymous]
    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        if (User.Identity?.IsAuthenticated != true)
        {
            return View();
        }

        var isAdmin = User.IsAdmin();
        var dto = await _dashboard.GetAsync(isAdmin ? null : User.Identity.Name, ct);
        var displayName = User.FindFirst(VaultClaimTypes.Display)?.Value ?? User.Identity.Name ?? string.Empty;

        return View("Dashboard", new DashboardViewModel
        {
            Username = displayName,
            IsAdmin = isAdmin,
            TotalActiveSecrets = dto.TotalActiveSecrets,
            DevelopmentCount = dto.DevelopmentCount,
            StagingCount = dto.StagingCount,
            ProductionCount = dto.ProductionCount,
            ExpiringWithin7Days = dto.ExpiringWithin7Days,
            UserCount = dto.UserCount,
            CriticalEventsLast24h = dto.CriticalEventsLast24h,
            RecentEvents = dto.RecentEvents,
            ExpiringSoon = dto.ExpiringSoon
        });
    }

    [AllowAnonymous]
    [HttpGet]
    public IActionResult Error(int? code)
    {
        var (title, message) = code switch
        {
            404 => ("Not found", "The requested resource does not exist, has expired, or has been shredded."),
            403 => ("Access denied", "The attribute-based access policy denied this request."),
            503 => ("Vault unavailable (fail-closed)", "The audit trail could not be written, so the operation was refused. No data was released."),
            _ => ("Something went wrong", "An unexpected error occurred. The incident has been logged.")
        };

        Response.StatusCode = code ?? 500;
        return View(new ErrorViewModel(code ?? 500, title, message, Activity.Current?.Id ?? HttpContext.TraceIdentifier));
    }
}
