using System.Security.Claims;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Web.Authorization;
using EclipsVault.Web.Extensions;
using EclipsVault.Web.Models;
using EclipsVault.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace EclipsVault.Web.Controllers;

/// <summary>
/// Two-stage sign-in: Argon2id password check issues only a short-lived MFA-pending
/// cookie; the full session principal (with ABAC attribute claims) is granted after
/// TOTP verification or first-time TOTP enrollment.
/// </summary>
[EnableRateLimiting(RateLimitPolicies.Authentication)]
public sealed class AccountController : Controller
{
    /// <summary>Session key holding the challenge issued for an in-flight passkey sign-in.</summary>
    private const string PasskeyAssertionChallengeKey = "passkey:assertion:challenge";

    private readonly IVaultAuthenticationService _auth;
    private readonly IPasskeyService _passkeys;
    private readonly IIpBlacklist _blacklist;
    private readonly IAuditSink _audit;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        IVaultAuthenticationService auth,
        IPasskeyService passkeys,
        IIpBlacklist blacklist,
        IAuditSink audit,
        ILogger<AccountController> logger)
    {
        _auth = auth;
        _passkeys = passkeys;
        _blacklist = blacklist;
        _audit = audit;
        _logger = logger;
    }

    private Task AuditRecoveryAsync(AuditAction action, Guid userId, string username, string details, CancellationToken ct)
        => _audit.WriteAsync(new AuditEntry { Action = action, ResourceType = "User", ResourceId = userId, ActorUserId = userId, ActorUsername = username, Details = details }, ct);

    [AllowAnonymous]
    [HttpGet]
    public IActionResult Login()
        => User.Identity?.IsAuthenticated == true
            ? RedirectToAction("Index", "Secrets")
            : View(new LoginViewModel());

    [AllowAnonymous]
    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model, CancellationToken ct)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var result = await _auth.ValidateCredentialsAsync(model.Username, model.Password, ct);
        if (result.Status == CredentialStatus.Invalid || result.User is null)
        {
            _logger.LogWarning("Password stage failed for {Username} from {SourceIp}",
                model.Username, HttpContext.Connection.RemoteIpAddress);
            ModelState.AddModelError(string.Empty, "Invalid username or password.");
            return View(model);
        }

        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, result.User.Id.ToString()),
                new Claim(ClaimTypes.Name, result.User.Username)
            ],
            AuthSchemes.MfaPending);
        await HttpContext.SignInAsync(AuthSchemes.MfaPending, new ClaimsPrincipal(identity));

        return RedirectToAction(result.Status == CredentialStatus.RequiresTotpEnrollment
            ? nameof(EnrollTotp)
            : nameof(Totp));
    }

    [Authorize(AuthenticationSchemes = AuthSchemes.MfaPending)]
    [HttpGet]
    public IActionResult Totp() => View(new TotpViewModel());

    [Authorize(AuthenticationSchemes = AuthSchemes.MfaPending)]
    [HttpPost]
    public async Task<IActionResult> Totp(TotpViewModel model, CancellationToken ct)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        if (GetMfaPendingUserId() is not { } userId)
        {
            return RedirectToAction(nameof(Login));
        }

        var user = await _auth.VerifyTotpAsync(userId, model.Code, ct);
        if (user is null)
        {
            ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
            return View(model);
        }

        await CompleteSignInAsync(user);
        return RedirectToAction("Index", "Secrets");
    }

    /// <summary>
    /// Alternative to the TOTP step for a user who has lost their authenticator: redeem a
    /// single-use recovery code. Guarded by the same MFA-pending cookie, so the password
    /// stage must already have succeeded.
    /// </summary>
    [Authorize(AuthenticationSchemes = AuthSchemes.MfaPending)]
    [HttpGet]
    public IActionResult RecoveryCode() => View(new RecoveryCodeViewModel());

    [Authorize(AuthenticationSchemes = AuthSchemes.MfaPending)]
    [HttpPost]
    public async Task<IActionResult> RecoveryCode(RecoveryCodeViewModel model, CancellationToken ct)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        if (GetMfaPendingUserId() is not { } userId)
        {
            return RedirectToAction(nameof(Login));
        }

        var user = await _auth.VerifyRecoveryCodeAsync(userId, model.Code, ct);
        if (user is null)
        {
            ModelState.AddModelError(string.Empty, "That recovery code is not valid, or it has already been used.");
            return View(model);
        }

        await CompleteSignInAsync(user);
        this.FlashInfo("You signed in with a recovery code — that code is now used up. Generate a new set from your profile if you're running low.");
        return RedirectToAction("Index", "Secrets");
    }

    [Authorize(AuthenticationSchemes = AuthSchemes.MfaPending)]
    [HttpGet]
    public async Task<IActionResult> EnrollTotp(CancellationToken ct)
    {
        if (GetMfaPendingUserId() is not { } userId)
        {
            return RedirectToAction(nameof(Login));
        }

        var enrollment = await _auth.BeginTotpEnrollmentAsync(userId, ct);
        return View(new EnrollTotpViewModel
        {
            SecretBase32 = enrollment.SecretBase32,
            QrCodeDataUri = TotpQrCode.PngDataUri(enrollment.OtpAuthUri)
        });
    }

    [Authorize(AuthenticationSchemes = AuthSchemes.MfaPending)]
    [HttpPost]
    public async Task<IActionResult> EnrollTotp(EnrollTotpViewModel model, CancellationToken ct)
    {
        if (GetMfaPendingUserId() is not { } userId)
        {
            return RedirectToAction(nameof(Login));
        }

        if (!ModelState.IsValid)
        {
            return await RedisplayEnrollmentAsync(userId, model, ct);
        }

        var user = await _auth.CompleteTotpEnrollmentAsync(userId, model.Code, ct);
        if (user is null)
        {
            ModelState.AddModelError(string.Empty, "The confirmation code did not match. Try again.");
            return await RedisplayEnrollmentAsync(userId, model, ct);
        }

        await CompleteSignInAsync(user);
        return RedirectToAction("Index", "Secrets");
    }

    /// <summary>
    /// Passwordless sign-in, stage one: issues WebAuthn assertion options. A registered
    /// passkey with user verification is a self-contained second factor, so a successful
    /// assertion grants the full session without a password or TOTP.
    /// </summary>
    [AllowAnonymous]
    [HttpPost]
    public async Task<IActionResult> PasskeyLoginBegin([FromBody] PasskeyLoginRequest? model, CancellationToken ct)
    {
        var options = await _passkeys.BeginAssertionAsync(model?.Username, ct);
        HttpContext.Session.SetString(PasskeyAssertionChallengeKey, options.Challenge);
        return Content(options.OptionsJson, "application/json");
    }

    /// <summary>Passwordless sign-in, stage two: verifies the assertion and issues the session.</summary>
    [AllowAnonymous]
    [HttpPost]
    public async Task<IActionResult> PasskeyLoginComplete([FromBody] PasskeyAssertionCompletion request, CancellationToken ct)
    {
        var challenge = HttpContext.Session.GetString(PasskeyAssertionChallengeKey);
        HttpContext.Session.Remove(PasskeyAssertionChallengeKey);
        if (string.IsNullOrEmpty(challenge))
        {
            return Json(new { success = false, error = "Sign-in timed out. Try again." });
        }

        var result = await _passkeys.CompleteAssertionAsync(challenge, request.Credential.GetRawText(), ct);
        if (!result.Success || result.User is null)
        {
            _logger.LogWarning("Passkey sign-in failed from {SourceIp}: {Error}",
                HttpContext.Connection.RemoteIpAddress, result.Error);
            return Json(new { success = false, error = result.Error ?? "Passkey sign-in failed." });
        }

        await CompleteSignInAsync(result.User);
        return Json(new { success = true, redirect = Url.Action("Index", "Secrets") });
    }

    /// <summary>
    /// Break-glass recovery for administrators locked out by the intrusion defence.
    /// The IP-blacklist middleware exempts only this endpoint; it demands all factors
    /// (password + TOTP) in one step, is restricted to TopSecret clearance, heavily
    /// rate limited, and every attempt is audited.
    /// </summary>
    [AllowAnonymous]
    [HttpGet]
    public IActionResult Recover() => View(new RecoverViewModel());

    [AllowAnonymous]
    [HttpPost]
    public async Task<IActionResult> Recover(RecoverViewModel model, CancellationToken ct)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var sourceIp = HttpContext.Connection.RemoteIpAddress;

        var credentials = await _auth.ValidateCredentialsAsync(model.Username, model.Password, ct);
        var user = credentials.Status == CredentialStatus.RequiresTotp && credentials.User is not null
            ? await _auth.VerifyTotpAsync(credentials.User.Id, model.Code, ct)
            : null;

        if (user is null)
        {
            _logger.LogWarning("Break-glass recovery failed for {Username} from {SourceIp}", model.Username, sourceIp);
            ModelState.AddModelError(string.Empty, "Recovery could not be completed with these credentials.");
            return View(model);
        }

        if (user.Clearance != ClearanceLevel.TopSecret)
        {
            await AuditRecoveryAsync(
                AuditAction.LoginFailed, user.Id, user.Username,
                "Break-glass recovery denied: insufficient clearance", ct);
            _logger.LogWarning("Break-glass recovery denied for {Username}: insufficient clearance", user.Username);
            ModelState.AddModelError(string.Empty, "Recovery could not be completed with these credentials.");
            return View(model);
        }

        var blockLifted = sourceIp is not null && _blacklist.UnblockAddress(sourceIp);
        await AuditRecoveryAsync(
            AuditAction.BreakGlassRecovery, user.Id, user.Username,
            $"Break-glass recovery from {sourceIp}; block lifted: {blockLifted}", ct);
        _logger.LogWarning(
            "Break-glass recovery completed by {Username} from {SourceIp}; block lifted: {BlockLifted}",
            user.Username, sourceIp, blockLifted);

        await CompleteSignInAsync(user);
        this.FlashSuccess(blockLifted
            ? "The intrusion-defence block on your network was lifted and your session restored."
            : "Access restored. Your network was not blocked.");
        return RedirectToAction("Index", "Home");
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Index", "Home");
    }

    /// <summary>TempData key used to hand ABAC denial reasons to the Denied page ('\n'-separated).</summary>
    internal const string DenialReasonsTempDataKey = "AbacDenialReasons";

    [HttpGet]
    public IActionResult Denied(Guid? secretId)
        => View(new AccessDeniedViewModel
        {
            Reasons = TempData[DenialReasonsTempDataKey] is string reasons
                ? reasons.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                : [],
            SecretId = secretId
        });

    private async Task<IActionResult> RedisplayEnrollmentAsync(Guid userId, EnrollTotpViewModel model, CancellationToken ct)
    {
        var enrollment = await _auth.BeginTotpEnrollmentAsync(userId, ct);
        model.SecretBase32 = enrollment.SecretBase32;
        model.QrCodeDataUri = TotpQrCode.PngDataUri(enrollment.OtpAuthUri);
        return View(model);
    }

    private async Task CompleteSignInAsync(UserDto user)
    {
        await HttpContext.SignOutAsync(AuthSchemes.MfaPending);

        var authTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(VaultClaimTypes.Display, string.IsNullOrWhiteSpace(user.DisplayName) ? user.Username : user.DisplayName),
                new Claim(VaultClaimTypes.AvatarVersion, DateTimeOffset.UtcNow.Ticks.ToString()),
                new Claim(VaultClaimTypes.Clearance, ((int)user.Clearance).ToString()),
                new Claim(VaultClaimTypes.Project, user.ProjectKey),
                new Claim(VaultClaimTypes.AuthTime, authTime)
            ],
            CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties { IsPersistent = false });

        _logger.LogInformation("User {Username} ({UserId}) completed multi-factor sign-in from {SourceIp}",
            user.Username, user.Id, HttpContext.Connection.RemoteIpAddress);
    }

    private Guid? GetMfaPendingUserId()
        => Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null;
}
