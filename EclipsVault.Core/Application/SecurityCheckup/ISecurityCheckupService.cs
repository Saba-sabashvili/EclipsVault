namespace EclipsVault.Core.Application.SecurityCheckup;

/// <summary>
/// Assembles the signed-in user's own security posture from the account services (two-step
/// enrolment, passkeys, backup codes, live devices) and scores it with
/// <see cref="SecurityCheckupEvaluator"/>. Strictly self-scoped: every read is keyed by the
/// caller's user id, so the checkup never discloses anything about another account.
/// </summary>
public interface ISecurityCheckupService
{
    /// <summary>
    /// Builds the checkup for one user, or null when the account no longer exists (mirrors the
    /// profile services, so the caller can send a stale session to sign out).
    /// </summary>
    Task<SecurityCheckup?> GetForUserAsync(Guid userId, CancellationToken ct);
}
