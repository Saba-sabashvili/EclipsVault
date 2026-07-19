using StackExchange.Redis;

namespace EclipsVault.Infrastructure.Distributed;

/// <summary>
/// Refuses to put the vault's security state in a Redis that anyone can write.
///
/// When Redis is enabled it holds the session-revocation markers, the intrusion IP blacklist, the
/// auth throttle and the encrypted-envelope cache. The first two are answers the vault trusts: an
/// unauthenticated Redis lets anyone who can reach the port delete a revocation marker — restoring
/// a session its owner had signed out of — or clear a block the intrusion response just placed.
/// "Sign out everywhere" then means nothing, and nor does the honey-token trap.
///
/// Redis listens on every interface and needs no password out of the box, so the insecure
/// configuration is the one you get by not thinking about it. This makes not thinking about it fail
/// at startup rather than in an incident.
/// </summary>
public static class RedisConnectionGuard
{
    public static void RequireAuthentication(RedisOptions options)
    {
        if (options.AllowUnauthenticated)
        {
            return;
        }

        ConfigurationOptions parsed;
        try
        {
            parsed = ConfigurationOptions.Parse(options.Configuration);
        }
        catch (ArgumentException ex)
        {
            throw new InvalidOperationException(
                $"Redis:Configuration could not be parsed ('{options.Configuration}'): {ex.Message}", ex);
        }

        // A password may also arrive as a Redis 6 ACL user; either satisfies this.
        if (!string.IsNullOrEmpty(parsed.Password) || !string.IsNullOrEmpty(parsed.User))
        {
            return;
        }

        throw new InvalidOperationException(
            "Redis is enabled with no password, and it is about to hold this vault's session revocations " +
            "and intrusion blocks — anyone who can reach it could restore a signed-out session or lift a " +
            "block. Add credentials to Redis:Configuration (for example " +
            "'localhost:6379,password=…', or ',user=…,password=…' for an ACL user). Set " +
            "Redis:AllowUnauthenticated=true only if the instance is genuinely unreachable by anything " +
            "else.");
    }
}
