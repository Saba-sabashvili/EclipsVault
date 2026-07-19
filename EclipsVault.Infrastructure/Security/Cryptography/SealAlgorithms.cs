namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// The values stored in <c>Secret.Algorithm</c>, and which of them bind their payload to its row.
///
/// The <c>Algorithm</c> column is unauthenticated data sitting next to the ciphertext, so anyone who
/// can rewrite one can rewrite the other. That makes "read this row the old, unbound way" an
/// attacker-selectable option and the binding trivially bypassable — which is why reading a legacy
/// blob is refused unless an operator explicitly turns it on for a migration
/// (<c>Crypto:AllowUnauthenticatedLegacyBlobs</c>), rather than inferred from the row itself.
/// </summary>
internal static class SealAlgorithms
{
    /// <summary>Local AES-GCM, payload bound to its row.</summary>
    public const string AesGcmLocal = "AES-256-GCM-AAD";

    /// <summary>Vault-wrapped DEK, payload bound to its row.</summary>
    public const string AesGcmVaultTransit = "AES-256-GCM-AAD+VaultTransit";

    /// <summary>Pre-binding local AES-GCM. Readable only during a migration.</summary>
    public const string LegacyAesGcmLocal = "AES-256-GCM";

    /// <summary>Pre-binding Vault-wrapped. Readable only during a migration.</summary>
    public const string LegacyAesGcmVaultTransit = "AES-256-GCM+VaultTransit";

    public static bool IsBound(string algorithm)
        => algorithm is AesGcmLocal or AesGcmVaultTransit;
}
