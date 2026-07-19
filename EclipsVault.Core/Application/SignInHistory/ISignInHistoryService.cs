namespace EclipsVault.Core.Application.SignInHistory;

/// <summary>Read-only, actor-scoped projection of the audit trail into a sign-in security timeline.</summary>
public interface ISignInHistoryService
{
    /// <summary>
    /// The signed-in user's own recent sign-in history, newest first. Scoped strictly to rows the
    /// user themselves generated (by user id, never the mutable username), so it never discloses
    /// anyone else's sign-ins.
    /// </summary>
    Task<SignInHistory> GetForUserAsync(Guid userId, CancellationToken ct);
}
