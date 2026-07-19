namespace EclipsVault.Web.Security;

/// <summary>
/// Where the ASP.NET Data Protection key ring lives. Those keys encrypt the authentication cookie,
/// antiforgery tokens, TempData and session — so they are not incidental plumbing: lose them and
/// every signed-in user is signed out; fail to share them and two replicas cannot read each other's
/// cookies, which looks to a user like being randomly logged out and to an operator like nothing at
/// all.
/// </summary>
public sealed class DataProtectionOptions
{
    public const string SectionName = "DataProtection";

    /// <summary>
    /// Directory holding the key ring. Must be durable and shared by every node — a mounted volume,
    /// not a container's own filesystem. The keys are encrypted at rest with the vault's KEK, so
    /// the directory needs to survive, not to be a secret in itself.
    /// </summary>
    public string? KeyRingPath { get; set; }

    /// <summary>
    /// Runs with per-process keys that vanish on restart. The default outside Development is to
    /// refuse rather than do this quietly: the damage is a slow bleed of sessions and 400s on form
    /// posts, which is easy to blame on anything else.
    /// </summary>
    public bool AllowEphemeralKeys { get; set; }
}
