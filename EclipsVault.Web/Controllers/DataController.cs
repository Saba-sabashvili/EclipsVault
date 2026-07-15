using System.Security.Claims;
using System.Text;
using System.Text.Json;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Web.Models;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

/// <summary>
/// Self-service "Your data": every authenticated user can see what account and security metadata
/// EclipsVault holds about them and download a portable copy (right-of-access / data portability).
/// Strictly self-scoped — the export is always built for the caller's own user id — and
/// metadata-only: secret values, passwords, authenticator seeds, and backup codes are never
/// included. Downloading is a deliberate, antiforgery-protected POST (so it can't be triggered by a
/// cross-site request or a drive-by prefetch) and is recorded in the audit trail.
/// </summary>
public sealed class DataController : Controller
{
    // Indented for humans; default (HTML-safe) escaping since the payload carries user-controlled
    // strings and is served for download rather than embedded anywhere.
    private static readonly JsonSerializerOptions ExportJson = new() { WriteIndented = true };

    private readonly IPersonalDataExportService _export;
    private readonly IAuditSink _audit;

    public DataController(IPersonalDataExportService export, IAuditSink audit)
    {
        _export = export;
        _audit = audit;
    }

    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var export = await _export.BuildForUserAsync(CurrentUserId(), ct);
        if (export is null)
        {
            return RedirectToAction("Logout", "Account");
        }

        return View(new DataExportViewModel { Export = export });
    }

    [HttpPost]
    public async Task<IActionResult> Download(CancellationToken ct)
    {
        var export = await _export.BuildForUserAsync(CurrentUserId(), ct);
        if (export is null)
        {
            return RedirectToAction("Logout", "Account");
        }

        // Record the export before handing the file over — a data export is a sensitive action, so
        // it belongs in the trail (and the user's own "My activity") whether or not the download
        // completes. Actor + source IP are filled by the sink from the request context.
        await _audit.WriteAsync(new AuditEntry
        {
            Action = AuditAction.PersonalDataExported,
            ResourceType = "Account",
            ResourceId = CurrentUserId(),
            Details = $"Exported personal data ({export.RecentActivity.Count} activity entries)"
        }, ct);

        var bytes = JsonSerializer.SerializeToUtf8Bytes(export, ExportJson);

        // The bundle mirrors sensitive account data; keep it out of any shared/browser cache.
        Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
        Response.Headers.Pragma = "no-cache";

        var stamp = export.GeneratedAtUtc.UtcDateTime.ToString("yyyyMMdd");
        var fileName = $"eclipsvault-data-{SafeSlug(export.Account.Username)}-{stamp}.json";

        // File(...) sets Content-Disposition: attachment; combined with the global nosniff header the
        // browser downloads it rather than rendering it.
        return File(bytes, "application/json", fileName);
    }

    /// <summary>Reduces a username to filename-safe characters (defence against header/path oddities).</summary>
    private static string SafeSlug(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '-');
        }
        var slug = sb.ToString().Trim('-');
        return slug.Length == 0 ? "account" : slug;
    }

    private Guid CurrentUserId()
        => Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : Guid.Empty;
}
