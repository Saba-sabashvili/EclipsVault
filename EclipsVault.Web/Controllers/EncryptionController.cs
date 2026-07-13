using EclipsVault.Web.Authorization;
using EclipsVault.Web.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

/// <summary>
/// Master-key lifecycle (TopSecret clearance only). Shows which KEK each secret is wrapped under and
/// runs a rotation that re-wraps everything under the current KEK. The current/retired keys themselves
/// come from the environment (or a KMS) — this page never sees raw key material.
/// </summary>
[Authorize(Policy = VaultPolicies.AdminOnly)]
public sealed class EncryptionController : Controller
{
    private readonly IKekRotationService _rotation;

    public EncryptionController(IKekRotationService rotation) => _rotation = rotation;

    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken ct)
        => View(await _rotation.GetStatusAsync(ct));

    [HttpPost]
    public async Task<IActionResult> Rotate(CancellationToken ct)
    {
        var result = await _rotation.RotateAsync(ct);
        var total = result.SecretsRewrapped + result.VersionsRewrapped;
        this.FlashSuccess(total == 0
            ? $"Everything is already wrapped under the current KEK ({result.CurrentKekId})."
            : $"Rotated {result.SecretsRewrapped} secret(s) and {result.VersionsRewrapped} version(s) to KEK {result.CurrentKekId}.");
        return RedirectToAction(nameof(Index));
    }
}
