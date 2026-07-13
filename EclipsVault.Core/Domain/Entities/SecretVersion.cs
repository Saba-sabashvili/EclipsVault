namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// A superseded value of a <see cref="Secret"/>, kept as its own envelope-encrypted
/// snapshot when the secret is rotated. Enables a rotation timeline, viewing a prior
/// value, and reverting. Holds real key material, so it is purged when the parent
/// secret is shredded or deleted.
/// </summary>
public class SecretVersion
{
    public Guid Id { get; set; }

    public Guid SecretId { get; set; }

    /// <summary>1-based sequence in which values were superseded (oldest = 1).</summary>
    public int VersionNumber { get; set; }

    /// <summary>nonce(12) | tag(16) | ciphertext — the archived payload sealed with its DEK.</summary>
    public byte[] Ciphertext { get; set; } = [];

    /// <summary>nonce(12) | tag(16) | encrypted DEK — the DEK sealed with the KEK.</summary>
    public byte[] WrappedDek { get; set; } = [];

    public string KekId { get; set; } = string.Empty;

    public string Algorithm { get; set; } = "AES-256-GCM";

    /// <summary>When this value was superseded (i.e. archived).</summary>
    public DateTimeOffset ArchivedAtUtc { get; set; }

    /// <summary>Username of whoever performed the rotation that archived this value.</summary>
    public string ArchivedBy { get; set; } = "system";

    /// <summary>Optional note supplied at rotation time (e.g. "quarterly rotation").</summary>
    public string? ChangeNote { get; set; }
}
