using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Tracks the most recent revocation instant per user. Any session issued at or
/// before that instant is rejected by cookie validation on its next request.
/// </summary>
public sealed class InMemorySessionRevocationService : ISessionRevocationService
{
    private readonly ConcurrentDictionary<Guid, DateTimeOffset> _revokedAt = new();
    private readonly ILogger<InMemorySessionRevocationService> _logger;

    public InMemorySessionRevocationService(ILogger<InMemorySessionRevocationService> logger) => _logger = logger;

    public void Revoke(Guid userId, DateTimeOffset revokedAtUtc)
    {
        _revokedAt.AddOrUpdate(
            userId,
            revokedAtUtc,
            (_, existing) => revokedAtUtc > existing ? revokedAtUtc : existing);
        _logger.LogWarning("All sessions for user {UserId} issued at or before {RevokedAtUtc} are now revoked", userId, revokedAtUtc);
    }

    public bool IsRevoked(Guid userId, DateTimeOffset sessionIssuedAtUtc)
        => _revokedAt.TryGetValue(userId, out var revokedAt) && sessionIssuedAtUtc <= revokedAt;
}
