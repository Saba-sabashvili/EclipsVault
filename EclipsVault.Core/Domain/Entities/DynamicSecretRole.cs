using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// A recipe for minting a short-lived backend credential on demand — not a stored value. The vault
/// holds no password for this: it runs <see cref="CreationStatements"/> when someone asks, hands the
/// result over once, and runs <see cref="RevocationStatements"/> when the lease ends.
///
/// The ABAC attributes are the same three a stored secret carries, so issuing is gated by the same
/// rule engine: a role is a vault resource like any other.
/// </summary>
public class DynamicSecretRole
{
    public Guid Id { get; set; }

    /// <summary>Short handle, e.g. "phoenix_db_reader". Also seeds the minted login's name.</summary>
    public string Name { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    /// <summary>ABAC resource attribute: owning project.</summary>
    public string ProjectKey { get; set; } = string.Empty;

    /// <summary>ABAC resource attribute: deployment environment.</summary>
    public SecretEnvironment Environment { get; set; } = SecretEnvironment.Development;

    /// <summary>ABAC resource attribute: sensitivity — the clearance floor for issuing.</summary>
    public SensitivityLevel Sensitivity { get; set; } = SensitivityLevel.Internal;

    public DynamicSecretBackend Backend { get; set; } = DynamicSecretBackend.SqlServer;

    /// <summary>
    /// Statements run to mint the credential, with {{name}}, {{password}} and {{expiration}}
    /// substituted. Defining a role is therefore a privileged act — the statements run with the
    /// vault's own backend rights — so roles are provisioned out of band, not through the UI.
    /// </summary>
    public string CreationStatements { get; set; } = string.Empty;

    /// <summary>Statements run to destroy the credential. Must be idempotent: the reaper may retry.</summary>
    public string RevocationStatements { get; set; } = string.Empty;

    /// <summary>Lease length when the caller does not ask for one.</summary>
    public int DefaultTtlMinutes { get; set; }

    /// <summary>Ceiling on a caller-requested lease — the blast radius of a leaked credential.</summary>
    public int MaxTtlMinutes { get; set; }

    public bool IsEnabled { get; set; } = true;

    public DateTimeOffset CreatedAtUtc { get; set; }
}
