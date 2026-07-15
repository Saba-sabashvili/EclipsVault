using EclipsVault.Web.Models;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

/// <summary>
/// The signed-in user's own sign-in history: a security-focused timeline of authentication events
/// — successful sign-ins (password, passkey, recovery code, step-up), rejected attempts, and the
/// account-lock lifecycle — drawn from the audit trail and scoped strictly to the caller. It exists
/// so anyone can spot an attempt they didn't make, especially one from a location they've never
/// signed in from. Read-only; it discloses nothing about any other user.
/// </summary>
public sealed class SignInsController : VaultController
{
    private readonly ISignInHistoryService _history;

    public SignInsController(ISignInHistoryService history) => _history = history;

    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken ct = default)
    {
        var history = await _history.GetForUserAsync(CurrentUserId(), ct);
        return View(new SignInHistoryViewModel { History = history });
    }

}
