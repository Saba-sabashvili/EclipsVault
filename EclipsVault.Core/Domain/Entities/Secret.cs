using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// An envelope-encrypted secret. The payload is encrypted with a single-use DEK
/// (AES-256-GCM); the DEK itself is stored wrapped by the master KEK. Plaintext
/// never touches this entity.
/// </summary>
public class Secret : IMutableEnvelope
{
    public Guid Id { get; set; }

    public string Name { get; set; } = string.Empty;

    /// <summary>ABAC resource attribute: owning project.</summary>
    public string ProjectKey { get; set; } = string.Empty;

    /// <summary>ABAC resource attribute: deployment environment.</summary>
    public SecretEnvironment Environment { get; set; } = SecretEnvironment.Development;

    /// <summary>ABAC resource attribute: sensitivity classification.</summary>
    public SensitivityLevel Sensitivity { get; set; } = SensitivityLevel.Internal;

    /// <summary>nonce(12) | tag(16) | ciphertext — payload sealed with the single-use DEK.</summary>
    public byte[] Ciphertext { get; set; } = [];

    /// <summary>nonce(12) | tag(16) | encrypted DEK — the DEK sealed with the master KEK.</summary>
    public byte[] WrappedDek { get; set; } = [];

    /// <summary>Identifier of the KEK that wrapped the DEK (supports KEK rotation).</summary>
    public string KekId { get; set; } = string.Empty;

    public string Algorithm { get; set; } = "AES-256-GCM";

    /// <summary>Marks a deliberately planted intrusion-detection decoy. Reading one trips the alarm.</summary>
    public bool IsHoneyToken { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }

    public DateTimeOffset? UpdatedAtUtc { get; set; }

    /// <summary>When set, the lifecycle worker shreds the key material after this instant.</summary>
    public DateTimeOffset? ExpiresAtUtc { get; set; }

    /// <summary>
    /// The <see cref="ExpiresAtUtc"/> value an expiry notice has already been sent for. Holding the
    /// deadline itself (not a bool) keeps the notice idempotent across every sweep, yet re-arms it
    /// automatically when the deadline moves. Bookkeeping only — writing it is not a domain change,
    /// so it is exempt from the SecretUpdated audit row.
    /// </summary>
    public DateTimeOffset? ExpiryNoticeSentForUtc { get; set; }

    /// <summary>True once key material has been destroyed. The row remains as a tombstone for the audit trail.</summary>
    public bool IsShredded { get; set; }

    public Guid CreatedByUserId { get; set; }

    /// <summary>
    /// Set when this secret <i>is</i> a real principal's password on a backend, and the vault is
    /// trusted to change it. Rotation then means the vault picks a new password, applies it
    /// upstream, and stores it — so the stored value and the live credential cannot drift apart.
    /// Null for an ordinary stored value, whose rotation is just re-encryption of what you paste in.
    /// </summary>
    public DynamicSecretBackend? RotationBackend { get; set; }

    /// <summary>The principal whose password this is — the handle rotation needs upstream.</summary>
    public string? RotationPrincipal { get; set; }

    /// <summary>True when the vault can rotate the real credential, not just the copy it holds.</summary>
    public bool IsManaged => RotationBackend is not null && !string.IsNullOrWhiteSpace(RotationPrincipal);

    /// <summary>Destroys the key material while keeping the row as an auditable tombstone.</summary>
    public void Shred(DateTimeOffset nowUtc)
    {
        IsShredded = true;
        Ciphertext = [];
        WrappedDek = [];
        UpdatedAtUtc = nowUtc;
    }
}
