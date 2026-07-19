namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Server-side kill switch for issued sessions. Cookie validation consults this on
/// every request, so revocation takes effect immediately regardless of cookie lifetime.
/// Backed by a shared store (Redis) in multi-node deployments so a revocation on one
/// node is honoured by every node.
/// </summary>
public interface ISessionRevocationService
{
    Task RevokeAsync(Guid userId, DateTimeOffset revokedAtUtc, CancellationToken ct = default);

    /// <summary>True when the user was revoked at or after the moment the session was issued.</summary>
    Task<bool> IsRevokedAsync(Guid userId, DateTimeOffset sessionIssuedAtUtc, CancellationToken ct = default);
}
