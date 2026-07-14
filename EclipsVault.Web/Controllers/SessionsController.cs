using System.Security.Claims;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Web.Authorization;
using EclipsVault.Web.Extensions;
using EclipsVault.Web.Models;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

/// <summary>
/// Self-service "signed-in devices": every authenticated user can see their own live sessions and
/// revoke an individual one (or all the others), the per-session complement to "sign out
/// everywhere". Strictly self-scoped — every registry call is keyed by the caller's own user id,
/// so a user can only ever see and revoke their own sessions, never anyone else's.
/// </summary>
public sealed class SessionsController : Controller
{
    private readonly ISessionRegistry _sessions;
    private readonly IAuditSink _audit;

    public SessionsController(ISessionRegistry sessions, IAuditSink audit)
    {
        _sessions = sessions;
        _audit = audit;
    }

    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var current = CurrentSessionId();
        var sessions = await _sessions.ListAsync(CurrentUserId(), ct);
        return View(new SessionsViewModel
        {
            CurrentSessionId = current,
            Sessions = sessions.Select(s => new ActiveSessionView
            {
                SessionId = s.SessionId,
                Device = s.Device,
                IpAddress = s.IpAddress,
                CreatedAtUtc = s.CreatedAtUtc,
                LastSeenAtUtc = s.LastSeenAtUtc,
                IsCurrent = current is { } c && c == s.SessionId
            }).ToList()
        });
    }

    [HttpPost]
    public async Task<IActionResult> Revoke(Guid id, CancellationToken ct)
    {
        // The session you're using now isn't revoked from here — that's what Sign out is for;
        // this page manages your *other* devices.
        if (CurrentSessionId() is { } current && current == id)
        {
            this.FlashInfo("That's the device you're using now — use Sign out for this one.");
            return RedirectToAction(nameof(Index));
        }

        await _sessions.RevokeAsync(CurrentUserId(), id, ct);
        await AuditRevokeAsync(id, ct);
        this.FlashSuccess("That session was signed out — it loses access on its next request.");
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> RevokeOthers(CancellationToken ct)
    {
        var userId = CurrentUserId();
        var current = CurrentSessionId();
        var others = (await _sessions.ListAsync(userId, ct))
            .Where(s => current is null || s.SessionId != current)
            .ToList();

        foreach (var s in others)
        {
            await _sessions.RevokeAsync(userId, s.SessionId, ct);
            await AuditRevokeAsync(s.SessionId, ct);
        }

        this.FlashSuccess(others.Count == 0
            ? "There were no other sessions to sign out."
            : $"Signed out {others.Count} other session{(others.Count == 1 ? "" : "s")}.");
        return RedirectToAction(nameof(Index));
    }

    private Task AuditRevokeAsync(Guid sessionId, CancellationToken ct)
        // Actor + source IP are filled by the sink from the (authenticated) request context.
        => _audit.WriteAsync(new AuditEntry
        {
            Action = AuditAction.SessionRevokedByUser,
            ResourceType = "Session",
            ResourceId = sessionId,
            Details = $"Revoked session {sessionId:N}"
        }, ct);

    private Guid CurrentUserId()
        => Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : Guid.Empty;

    private Guid? CurrentSessionId()
        => Guid.TryParse(User.FindFirstValue(VaultClaimTypes.SessionId), out var id) ? id : null;
}
