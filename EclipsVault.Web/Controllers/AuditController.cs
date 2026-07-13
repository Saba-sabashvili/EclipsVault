using EclipsVault.Web.Authorization;
using EclipsVault.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

/// <summary>Read-only viewer over the immutable audit trail.</summary>
[Authorize(Policy = VaultPolicies.AdminOnly)]
public sealed class AuditController : Controller
{
    private const int PageSize = 200;

    private readonly IAuditLogReader _reader;

    public AuditController(IAuditLogReader reader) => _reader = reader;

    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken ct)
        => View(new AuditIndexViewModel
        {
            Entries = await _reader.ListRecentAsync(PageSize, username: null, ct)
        });

    /// <summary>Re-walks the hash chain and shows whether the trail has been tampered with.</summary>
    [HttpPost]
    public async Task<IActionResult> Verify(CancellationToken ct)
        => View(nameof(Index), new AuditIndexViewModel
        {
            Entries = await _reader.ListRecentAsync(PageSize, username: null, ct),
            Integrity = await _reader.VerifyIntegrityAsync(ct)
        });
}
