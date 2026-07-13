namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Server-side kill switch for issued sessions. Cookie validation consults this on
/// every request, so revocation takes effect immediately regardless of cookie lifetime.
/// </summary>
public interface ISessionRevocationService
{
    void Revoke(Guid userId, DateTimeOffset revokedAtUtc);

    /// <summary>True when the user was revoked at or after the moment the session was issued.</summary>
    bool IsRevoked(Guid userId, DateTimeOffset sessionIssuedAtUtc);
}
