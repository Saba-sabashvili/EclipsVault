namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Where dynamic secrets and managed rotation do their work — the database whose principals the
/// vault mints, drops, and re-passwords.
///
/// <para>
/// This is a <em>separate</em> connection from the vault's own, deliberately, and it is the whole
/// point of this type. Creating and dropping logins requires server-level rights
/// (<c>ALTER ANY LOGIN</c> on SQL Server), which permit changing the password of any principal on
/// that instance. Running those statements over the vault's own connection would mean the vault's
/// login had to hold them, and a compromise of the running application would then escalate to
/// control of the database that stores the audit trail — collapsing the "least privilege at rest"
/// property that bounds the blast radius of an app compromise. Keeping the privileged credential
/// separate lets it point at a different server entirely, which is also what an operator actually
/// wants: credentials minted on <em>their</em> application databases, not on the vault's.
/// </para>
///
/// <para>
/// There is no fallback to the vault's connection. If this is unset, minting and rotation refuse —
/// the same fail-closed posture the rest of the vault takes, because the alternative is quietly
/// requiring a privilege the operator never agreed to grant.
/// </para>
/// </summary>
public sealed class DynamicSecretTargetOptions
{
    public const string SectionName = "DynamicSecrets";

    /// <summary>
    /// Connection string for the managed target. Supply it the way you supply any other secret —
    /// an environment variable or a mounted file, never committed configuration.
    /// </summary>
    public string? TargetConnectionString { get; set; }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(TargetConnectionString);
}
