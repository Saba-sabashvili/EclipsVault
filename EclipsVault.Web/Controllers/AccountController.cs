using EclipsVault.Core.Application.Sso;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Web.Authentication;
using EclipsVault.Web.Authorization;
using EclipsVault.Web.Extensions;
using EclipsVault.Web.Models;
using EclipsVault.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

/// <summary>
/// Two-stage sign-in: Argon2id password check issues only a short-lived MFA-pending
/// cookie; the full session principal (with ABAC attribute claims) is granted after
/// TOTP verification or first-time TOTP enrollment.
/// </summary>
// Default-deny at the class, opened per action. This is the one controller whose whole job is to
// serve callers who are not yet signed in, so the anonymous surface here is the largest in the
// vault — which is exactly why it is declared action by action with [AllowAnonymous] rather than
// left to a policy configured in another file.
[Authorize]
[ServiceFilter(typeof(AuthThrottleFilter))]
public sealed class AccountController : Controller
{
    /// <summary>Session key holding the challenge issued for an in-flight passkey sign-in.</summary>
    private const string PasskeyAssertionChallengeKey = "passkey:assertion:challenge";

    private readonly IVaultAuthenticationService _auth;
    private readonly IPasskeyService _passkeys;
    private readonly IIpBlacklist _blacklist;
    private readonly ISessionRegistry _sessions;
    private readonly IAuditSink _audit;
    private readonly ISsoSignInService _sso;
    private readonly ISsoAvailability _ssoAvailability;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        IVaultAuthenticationService auth,
        IPasskeyService passkeys,
        IIpBlacklist blacklist,
        ISessionRegistry sessions,
        IAuditSink audit,
        ISsoSignInService sso,
        ISsoAvailability ssoAvailability,
        ILogger<AccountController> logger)
    {
        _auth = auth;
        _passkeys = passkeys;
        _blacklist = blacklist;
        _sessions = sessions;
        _audit = audit;
        _sso = sso;
        _ssoAvailability = ssoAvailability;
        _logger = logger;
    }

    private Task AuditRecoveryAsync(AuditAction action, Guid userId, string username, string details, CancellationToken ct)
        => _audit.WriteAsync(new AuditEntry { Action = action, ResourceType = "User", ResourceId = userId, ActorUserId = userId, ActorUsername = username, Details = details }, ct);

    [AllowAnonymous]
    [HttpGet]
    public IActionResult Login()
        => User.Identity?.IsAuthenticated == true
            ? RedirectToAction("Index", "Secrets")
            : View(Decorate(new LoginViewModel()));

    /// <summary>Stamps the SSO button's state onto the model — it is not part of the posted form.</summary>
    private LoginViewModel Decorate(LoginViewModel model)
    {
        model.SsoEnabled = _ssoAvailability.Enabled;
        model.SsoDisplayName = _ssoAvailability.DisplayName;
        return model;
    }

    [AllowAnonymous]
    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model, CancellationToken ct)
    {
        if (!ModelState.IsValid)
        {
            return View(Decorate(model));
        }

        var result = await _auth.ValidateCredentialsAsync(model.Username, model.Password, ct);
        if (result.Status == CredentialStatus.Invalid || result.User is null)
        {
            _logger.LogWarning("Password stage failed for {Username} from {SourceIp}",
                model.Username, HttpContext.Connection.RemoteIpAddress);
            ModelState.AddModelError(string.Empty, "Invalid username or password.");
            return View(Decorate(model));
        }

        var principal = VaultClaimsFactory.CreatePendingMfaPrincipal(result.User);
        await HttpContext.SignInAsync(AuthSchemes.MfaPending, principal);

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

        var blockLifted = sourceIp is not null && await _blacklist.UnblockAddressAsync(sourceIp, ct);
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

    /// <summary>Hands off to the identity provider. Nothing is decided here.</summary>
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public IActionResult ExternalLogin()
        => Challenge(
            new AuthenticationProperties { RedirectUri = Url.Action(nameof(ExternalCallback)) },
            AuthSchemes.Oidc);

    /// <summary>
    /// Back from the identity provider. It has proved who they are; everything about whether they
    /// may in — and whether they are finished authenticating — is the vault's call, made in Core by
    /// <see cref="ISsoSignInService"/> and audited there, refusals included.
    /// </summary>
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ExternalCallback(CancellationToken ct)
    {
        var result = await HttpContext.AuthenticateAsync(AuthSchemes.OidcCorrelation);
        // The correlation principal exists only to carry the IdP's answer across this one redirect.
        // Drop it immediately: it is not a session and must never be mistaken for one.
        await HttpContext.SignOutAsync(AuthSchemes.OidcCorrelation);

        if (!result.Succeeded || result.Principal is null)
        {
            this.FlashError("Single sign-on did not complete. Please try again.");
            return RedirectToAction(nameof(Login));
        }

        var identity = ExternalIdentityReader.Read(result.Principal);
        var decision = await _sso.SignInAsync(identity, ct);

        if (decision.Outcome != SsoOutcome.Linked || decision.User is null)
        {
            // One message for every refusal. The trail records exactly which it was; the sign-in
            // page must not tell an anonymous caller whether an address has an account here.
            _logger.LogWarning("SSO sign-in refused ({Outcome}) for subject {Subject} from {Issuer}",
                decision.Outcome, identity.Subject, identity.Issuer);
            this.FlashError("Single sign-on did not grant access to this vault. Contact an administrator.");
            return RedirectToAction(nameof(Login));
        }

        var user = decision.User;
        if (decision.SecondFactorSatisfied)
        {
            await CompleteSignInAsync(user);
            return RedirectToAction("Index", "Dashboard");
        }

        // The IdP proved one factor; this vault wants its own. Rejoin the ordinary flow rather than
        // inventing a second one — TOTP, enrollment and recovery codes all already live there.
        var pending = VaultClaimsFactory.CreatePendingMfaPrincipal(user);
        await HttpContext.SignInAsync(AuthSchemes.MfaPending, pending);
        return RedirectToAction(user.TotpEnabled ? nameof(Totp) : nameof(EnrollTotp));
    }

    private async Task CompleteSignInAsync(UserDto user)
    {
        await HttpContext.SignOutAsync(AuthSchemes.MfaPending);

        // A fresh per-session id lets this device be revoked on its own, distinct from the
        // account-wide "sign out everywhere" kill switch. It rides in the cookie as a claim.
        var sessionId = Guid.NewGuid();
        var principal = VaultClaimsFactory.CreateSessionPrincipal(user, sessionId, DateTimeOffset.UtcNow);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties { IsPersistent = false });

        var now = DateTimeOffset.UtcNow;
        await _sessions.RecordSeenAsync(new SessionObservation(
            user.Id,
            sessionId,
            UserAgentSummary.Describe(Request.Headers.UserAgent.ToString()),
            HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            now,
            now + SessionDefaults.InteractiveLifetime), HttpContext.RequestAborted);

        _logger.LogInformation("User {Username} ({UserId}) completed multi-factor sign-in from {SourceIp}",
            user.Username, user.Id, HttpContext.Connection.RemoteIpAddress);
    }

    private Guid? GetMfaPendingUserId() => User.GetUserIdOrNull();
}
