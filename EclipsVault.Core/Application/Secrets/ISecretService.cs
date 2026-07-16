
namespace EclipsVault.Core.Application.Secrets;

/// <summary>Application-layer facade for the secret lifecycle. Controllers depend on this, never on persistence.</summary>
public interface ISecretService
{
    Task<IReadOnlyList<SecretSummaryDto>> ListAsync(CancellationToken ct);

    /// <summary>Metadata view. Trips the honey-token trap and writes a fail-closed audit row.</summary>
    Task<SecretDetailsDto> GetDetailsAsync(Guid id, CancellationToken ct);

    /// <summary>Decrypts the payload. Audit row is committed BEFORE any decryption happens (fail-closed).</summary>
    Task<RevealedSecretDto> RevealAsync(Guid id, CancellationToken ct);

    Task<Guid> CreateAsync(CreateSecretRequest request, CancellationToken ct);

    /// <summary>Sets a new value, archiving the current one as a version first. Audited.</summary>
    /// <summary>
    /// Replaces the value, archiving the current one as a version. <paramref name="renewTtlDays"/>
    /// resets the expiry to that many days from now — the renewal the "Expiring soon" panel points
    /// at; null leaves the existing deadline untouched.
    /// </summary>
    Task RotateAsync(Guid id, string newValue, string? changeNote, int? renewTtlDays, CancellationToken ct);

    /// <summary>
    /// Rotates a <b>managed</b> secret: the vault picks a new password, changes the real principal
    /// on its backend, and stores the result — so the stored value and the live credential move
    /// together instead of an operator changing one and pasting the other. Throws
    /// <c>VaultAdminException</c> if the secret is not bound to a backend principal.
    /// </summary>
    Task RotateManagedAsync(Guid id, int? renewTtlDays, CancellationToken ct);

    /// <summary>Lists the archived (superseded) values of a secret, newest first. Metadata only.</summary>
    Task<IReadOnlyList<SecretVersionDto>> ListVersionsAsync(Guid id, CancellationToken ct);

    /// <summary>Decrypts an archived version. Audit row is committed BEFORE any decryption (fail-closed).</summary>
    Task<RevealedSecretDto> RevealVersionAsync(Guid id, Guid versionId, CancellationToken ct);

    /// <summary>Reverts the secret's live value to an archived version (archiving the current value first). Audited.</summary>
    Task RestoreVersionAsync(Guid id, Guid versionId, CancellationToken ct);

    Task DeleteAsync(Guid id, CancellationToken ct);
}
