using EclipsVault.Web.Extensions;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

/// <summary>
/// Base class for the interactive, cookie-authenticated MVC controllers. It exposes the signed-in
/// principal's identity through small, fail-closed accessors so no controller re-implements claim
/// parsing — the logic lives once in <see cref="ClaimsPrincipalExtensions"/>.
/// </summary>
public abstract class VaultController : Controller
{
    /// <summary>The signed-in user's id, or <see cref="Guid.Empty"/> when absent (fail-closed).</summary>
    protected Guid CurrentUserId() => User.GetUserId();

    /// <summary>The signed-in user's immutable login username (the audit anchor), or empty.</summary>
    protected string CurrentUsername() => User.GetUsername();

    /// <summary>This device's session id, or null when the principal carries none.</summary>
    protected Guid? CurrentSessionId() => User.GetSessionId();
}
