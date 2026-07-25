using EclipsVault.Core.Application.Mfa;
using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Core.Domain.Exceptions;

namespace EclipsVault.Core.Application.Authentication;

/// <summary>
/// Password (Argon2id) + TOTP verification workflow. Every outcome — success or
/// failure — is written to the audit trail through the fail-closed <see cref="IAuditSink"/>.
/// </summary>
public sealed class VaultAuthenticationService : IVaultAuthenticationService
{
    // Verified against when the username is unknown, so response timing does not
    // reveal whether an account exists.
    private static readonly byte[] DummyHash = new byte[32];
    private static readonly byte[] DummySalt = new byte[16];

    private readonly IUserRepository _users;
    private readonly IPasswordHasher _hasher;
    private readonly ITotpService _totp;
    private readonly IMfaRecoveryCodeRepository _recoveryCodes;
    private readonly LockoutPolicy _lockout;
    private readonly IAuditSink _audit;
    private readonly TimeProvider _clock;

    public VaultAuthenticationService(
        IUserRepository users,
        IPasswordHasher hasher,
        ITotpService totp,
        IMfaRecoveryCodeRepository recoveryCodes,
        LockoutPolicy lockout,
        IAuditSink audit,
        TimeProvider clock)
    {
        _users = users;
        _hasher = hasher;
        _totp = totp;
        _recoveryCodes = recoveryCodes;
        _lockout = lockout;
        _audit = audit;
        _clock = clock;
    }

    private Task AuditUserAsync(AuditAction action, Guid? userId, string username, string? details, CancellationToken ct)
        => _audit.WriteUserEventAsync(action, userId, username, details, ct);

    public async Task<CredentialCheckResult> ValidateCredentialsAsync(string usernameOrEmail, string password, CancellationToken ct)
    {
        var user = await _users.FindByUsernameOrEmailAsync(usernameOrEmail, ct);
        if (user is null)
        {
            _hasher.Verify(password, DummyHash, DummySalt);
            await AuditUserAsync(AuditAction.LoginFailed, null, usernameOrEmail, "Unknown username or email", ct);
            return CredentialCheckResult.Invalid;
        }

        // A locked account is rejected before the (costly) password check.
        if (user.IsLockedOut(_clock.GetUtcNow()))
        {
            await AuditUserAsync(AuditAction.LoginFailed, user.Id, user.Username, "Account is locked out", ct);
            return CredentialCheckResult.Invalid;
        }

        if (!_hasher.Verify(password, user.PasswordHash, user.PasswordSalt))
        {
            await RegisterFailureAsync(user, AuditAction.LoginFailed, "Password verification failed", ct);
            return CredentialCheckResult.Invalid;
        }

        // Disabled accounts fail after the password check so timing does not reveal the state.
        if (user.IsDisabled)
        {
            await AuditUserAsync(AuditAction.LoginFailed, user.Id, user.Username, "Account is disabled", ct);
            return CredentialCheckResult.Invalid;
        }

        var status = user.TotpEnabled ? CredentialStatus.RequiresTotp : CredentialStatus.RequiresTotpEnrollment;
        return new CredentialCheckResult(status, UserDto.From(user));
    }

    public async Task<UserDto?> VerifyTotpAsync(Guid userId, string code, CancellationToken ct)
    {
        var user = await _users.FindByIdAsync(userId, ct);
        if (user is null || !user.TotpEnabled || user.TotpSecret is null)
        {
            return null;
        }

        if (user.IsLockedOut(_clock.GetUtcNow()))
        {
            await AuditUserAsync(AuditAction.TotpFailed, user.Id, user.Username, "Account is locked out", ct);
            return null;
        }

        // A code already spent is refused here exactly like a wrong one — including the failure
        // count — so replaying an observed code is no cheaper than guessing.
        if (!_totp.TryValidateCode(user.TotpSecret, code, user.LastTotpStep, out var step))
        {
            await RegisterFailureAsync(user, AuditAction.TotpFailed, "TOTP verification failed", ct);
            return null;
        }

        user.LastTotpStep = step;
        await _users.UpdateAsync(user, ct);

        await ResetLockoutAsync(user, ct);
        await AuditUserAsync(AuditAction.LoginSucceeded, user.Id, user.Username, "Password + TOTP", ct);
        return UserDto.From(user);
    }

    public async Task<UserDto?> VerifyRecoveryCodeAsync(Guid userId, string code, CancellationToken ct)
    {
        var user = await _users.FindByIdAsync(userId, ct);
        if (user is null || !user.TotpEnabled)
        {
            return null;
        }

        if (user.IsLockedOut(_clock.GetUtcNow()))
        {
            await AuditUserAsync(AuditAction.TotpFailed, user.Id, user.Username, "Account is locked out", ct);
            return null;
        }

        var normalized = RecoveryCodeFormat.Normalize(code);
        var unused = await _recoveryCodes.ListUnusedAsync(userId, ct);
        var match = FindMatchingCode(unused, normalized);
        if (match is null)
        {
            await RegisterFailureAsync(user, AuditAction.TotpFailed, "Recovery code verification failed", ct);
            return null;
        }

        match.UsedAtUtc = _clock.GetUtcNow();
        await _recoveryCodes.MarkUsedAsync(match, ct);
        await ResetLockoutAsync(user, ct);

        var remaining = await _recoveryCodes.CountUnusedAsync(userId, ct);
        await AuditUserAsync(AuditAction.RecoveryCodeUsed, user.Id, user.Username, $"Recovery code redeemed; {remaining} remaining", ct);
        await AuditUserAsync(AuditAction.LoginSucceeded, user.Id, user.Username, "Password + recovery code", ct);
        return UserDto.From(user);
    }

    /// <summary>
    /// Verifies the input against every unused code so a wrong code costs the same
    /// regardless of which (if any) it would have matched — no early-out timing signal.
    /// </summary>
    private MfaRecoveryCode? FindMatchingCode(IReadOnlyList<MfaRecoveryCode> codes, string normalized)
    {
        MfaRecoveryCode? match = null;
        foreach (var candidate in codes)
        {
            if (_hasher.Verify(normalized, candidate.CodeHash, candidate.Salt))
            {
                match = candidate;
            }
        }

        return match;
    }

    public async Task<TotpEnrollmentDto> BeginTotpEnrollmentAsync(Guid userId, CancellationToken ct)
    {
        var user = await _users.FindByIdAsync(userId, ct)
                   ?? throw new TotpEnrollmentException($"User '{userId}' was not found.");

        if (user.TotpEnabled)
        {
            throw new TotpEnrollmentException("TOTP is already enrolled for this account.");
        }

        // Idempotent until enrollment completes: keep the pending secret stable so a
        // mistyped confirmation code does not silently rotate it.
        if (string.IsNullOrEmpty(user.TotpSecret))
        {
            user.TotpSecret = _totp.GenerateSecret();
            await _users.UpdateAsync(user, ct);
        }

        return new TotpEnrollmentDto(user.TotpSecret, _totp.BuildOtpAuthUri(user.TotpSecret, user.Username));
    }

    public async Task<UserDto?> CompleteTotpEnrollmentAsync(Guid userId, string code, CancellationToken ct)
    {
        var user = await _users.FindByIdAsync(userId, ct);
        if (user is null || user.TotpEnabled || string.IsNullOrEmpty(user.TotpSecret))
        {
            return null;
        }

        if (!_totp.TryValidateCode(user.TotpSecret, code, user.LastTotpStep, out var step))
        {
            await AuditUserAsync(AuditAction.TotpFailed, user.Id, user.Username, "Enrollment confirmation failed", ct);
            return null;
        }

        user.TotpEnabled = true;
        // Enrollment spends a step like any other use: the code just typed to prove the authenticator
        // works must not then be replayable as the first sign-in.
        user.LastTotpStep = step;
        user.FailedAccessCount = 0;
        user.LockedUntilUtc = null;
        await _users.UpdateAsync(user, ct);
        await AuditUserAsync(AuditAction.TotpEnrolled, user.Id, user.Username, null, ct);
        await AuditUserAsync(AuditAction.LoginSucceeded, user.Id, user.Username, "Password + TOTP enrollment", ct);
        return UserDto.From(user);
    }

    /// <summary>Increments the failure counter, locking the account when the threshold is reached, then audits.</summary>
    private async Task RegisterFailureAsync(User user, AuditAction failureAction, string reason, CancellationToken ct)
    {
        user.FailedAccessCount++;
        var locked = user.FailedAccessCount >= _lockout.MaxFailedAttempts;
        if (locked)
        {
            user.LockedUntilUtc = _clock.GetUtcNow() + _lockout.LockoutDuration;
            user.FailedAccessCount = 0;
        }

        await _users.UpdateAsync(user, ct);
        await AuditUserAsync(failureAction, user.Id, user.Username, reason, ct);
        if (locked)
        {
            await AuditUserAsync(
                AuditAction.AccountLockedOut, user.Id, user.Username,
                $"Locked until {user.LockedUntilUtc:u} after {_lockout.MaxFailedAttempts} failed attempts", ct);
        }
    }

    private async Task ResetLockoutAsync(User user, CancellationToken ct)
    {
        if (user.FailedAccessCount == 0 && user.LockedUntilUtc is null)
        {
            return;
        }

        user.FailedAccessCount = 0;
        user.LockedUntilUtc = null;
        await _users.UpdateAsync(user, ct);
    }

}
