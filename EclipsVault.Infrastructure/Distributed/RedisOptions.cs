namespace EclipsVault.Infrastructure.Distributed;

/// <summary>
/// Connection and key-namespacing settings for the Redis-backed distributed state
/// (session revocation, the intrusion IP blacklist, and the encrypted-envelope cache).
/// When <see cref="Enabled"/> is false the app uses the in-process implementations, so a
/// single-node deployment needs no Redis at all.
/// </summary>
public sealed class RedisOptions
{
    public const string SectionName = "Redis";

    /// <summary>Turn on Redis-backed shared state. Required for horizontal scale-out.</summary>
    public bool Enabled { get; set; }

    /// <summary>StackExchange.Redis connection string, e.g. "localhost:6379" or "cache:6379,ssl=true".</summary>
    public string Configuration { get; set; } = "localhost:6379";

    /// <summary>Prefix applied to every key so a shared Redis can host multiple apps/environments.</summary>
    public string InstanceName { get; set; } = "eclipsvault";

    /// <summary>
    /// How long a per-user revocation marker is retained. Must exceed the maximum session
    /// lifetime so a revoked-but-idle session can never outlive its marker.
    /// </summary>
    public int RevocationRetentionHours { get; set; } = 24;
}
