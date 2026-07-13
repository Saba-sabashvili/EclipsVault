using System.Text.Json;
using EclipsVault.Web.Authorization;
using EclipsVault.Web.Extensions;
using EclipsVault.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

/// <summary>Viewer over the immutable audit trail, plus signed-checkpoint attestation and export.</summary>
[Authorize(Policy = VaultPolicies.AdminOnly)]
public sealed class AuditController : Controller
{
    private const int PageSize = 200;

    private static readonly JsonSerializerOptions BundleJson = new() { WriteIndented = true };

    private readonly IAuditLogReader _reader;
    private readonly IAuditCheckpointService _checkpoints;

    public AuditController(IAuditLogReader reader, IAuditCheckpointService checkpoints)
    {
        _reader = reader;
        _checkpoints = checkpoints;
    }

    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken ct)
        => View(await BuildAsync(integrity: null, ct));

    /// <summary>Re-walks the hash chain and shows whether the trail has been tampered with.</summary>
    [HttpPost]
    public async Task<IActionResult> Verify(CancellationToken ct)
        => View(nameof(Index), await BuildAsync(await _reader.VerifyIntegrityAsync(ct), ct));

    /// <summary>Signs the current chain head so its integrity can later be proven to an outside party.</summary>
    [HttpPost]
    public async Task<IActionResult> CreateCheckpoint(CancellationToken ct)
    {
        var checkpoint = await _checkpoints.CreateCheckpointAsync(ct);
        if (checkpoint is null)
        {
            this.FlashInfo("There are no audit entries to checkpoint yet.");
        }
        else
        {
            this.FlashSuccess($"Signed checkpoint created at sequence {checkpoint.Sequence} with key {checkpoint.SigningKeyId}.");
        }

        return RedirectToAction(nameof(Index));
    }

    /// <summary>
    /// Downloads a self-contained, signed bundle of the whole audit trail. It can be verified
    /// offline with the <c>EclipsVault.AuditVerifier</c> tool — no access to this app or its
    /// database required.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> Export(CancellationToken ct)
    {
        var bundle = await _checkpoints.ExportAsync(ct);
        var json = JsonSerializer.SerializeToUtf8Bytes(bundle, BundleJson);
        var fileName = $"eclipsvault-audit-bundle-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.json";
        return File(json, "application/json", fileName);
    }

    private async Task<AuditIndexViewModel> BuildAsync(AuditIntegrityReport? integrity, CancellationToken ct)
        => new()
        {
            Entries = await _reader.ListRecentAsync(PageSize, username: null, ct),
            Integrity = integrity,
            LatestCheckpoint = await _checkpoints.GetLatestAsync(ct),
            SigningKeyId = _checkpoints.SigningKeyId
        };
}
