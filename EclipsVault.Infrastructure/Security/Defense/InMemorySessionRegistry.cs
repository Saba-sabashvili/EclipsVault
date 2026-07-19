using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Tracks live sessions per user in process memory. Suitable for a single node; multi-node
/// deployments use the Redis-backed registry so every node sees the same sessions and a
/// revocation on one node is honoured on all. Revoked sessions are held as tombstones so a
/// lingering cookie is rejected and cannot resurrect its session by simply being seen again.
/// </summary>
public sealed class InMemorySessionRegistry : ISessionRegistry
{
    // Only rewrite last-seen once it has drifted by this much — keeps the per-request touch trivial.
    private static readonly TimeSpan TouchThrottle = TimeSpan.FromSeconds(60);
    // A tombstone older than any session's lifetime is moot (the cookie has expired anyway).
    private static readonly TimeSpan TombstoneRetention = TimeSpan.FromHours(12);

    private sealed record Entry(
        Guid SessionId, string Device, string IpAddress,
        DateTimeOffset CreatedAtUtc, DateTimeOffset LastSeenAtUtc, DateTimeOffset ExpiresAtUtc);

    private readonly ConcurrentDictionary<Guid, ConcurrentDictionary<Guid, Entry>> _sessions = new();
    private readonly ConcurrentDictionary<(Guid User, Guid Session), DateTimeOffset> _revokedAt = new();
    private readonly ILogger<InMemorySessionRegistry> _logger;

    public InMemorySessionRegistry(ILogger<InMemorySessionRegistry> logger) => _logger = logger;

    public Task RecordSeenAsync(SessionObservation o, CancellationToken ct = default)
    {
        // A revoked session must never come back to life just because a request carried its cookie.
        if (_revokedAt.ContainsKey((o.UserId, o.SessionId)))
        {
            return Task.CompletedTask;
        }

        var forUser = _sessions.GetOrAdd(o.UserId, _ => new ConcurrentDictionary<Guid, Entry>());
        forUser.AddOrUpdate(
            o.SessionId,
            _ => new Entry(o.SessionId, o.Device, o.IpAddress, o.SeenAtUtc, o.SeenAtUtc, o.ExpiresAtUtc),
            (_, existing) => o.SeenAtUtc - existing.LastSeenAtUtc >= TouchThrottle
                ? existing with { LastSeenAtUtc = o.SeenAtUtc, ExpiresAtUtc = o.ExpiresAtUtc, IpAddress = o.IpAddress }
                : existing);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<ActiveSession>> ListAsync(Guid userId, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        IReadOnlyList<ActiveSession> list = [];

        if (_sessions.TryGetValue(userId, out var forUser))
        {
            // Drop expired entries as we pass so the map does not grow without bound.
            foreach (var e in forUser.Values.Where(e => e.ExpiresAtUtc <= now))
            {
                forUser.TryRemove(e.SessionId, out _);
            }

            list = forUser.Values
                .Where(e => e.ExpiresAtUtc > now && !_revokedAt.ContainsKey((userId, e.SessionId)))
                .OrderByDescending(e => e.LastSeenAtUtc)
                .Select(e => new ActiveSession(e.SessionId, e.Device, e.IpAddress, e.CreatedAtUtc, e.LastSeenAtUtc))
                .ToList();
        }

        return Task.FromResult(list);
    }

    public Task RevokeAsync(Guid userId, Guid sessionId, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        _revokedAt[(userId, sessionId)] = now;
        if (_sessions.TryGetValue(userId, out var forUser))
        {
            forUser.TryRemove(sessionId, out _);
        }

        // Revocations are rare, so sweep stale tombstones here to bound memory.
        foreach (var kvp in _revokedAt)
        {
            if (now - kvp.Value > TombstoneRetention)
            {
                _revokedAt.TryRemove(kvp.Key, out _);
            }
        }

        _logger.LogInformation("Session {SessionId} for user {UserId} was revoked", sessionId, userId);
        return Task.CompletedTask;
    }

    public Task<bool> IsRevokedAsync(Guid userId, Guid sessionId, CancellationToken ct = default)
        => Task.FromResult(_revokedAt.ContainsKey((userId, sessionId)));
}
