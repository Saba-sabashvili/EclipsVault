
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
    Task RotateAsync(Guid id, string newValue, string? changeNote, CancellationToken ct);

    /// <summary>Lists the archived (superseded) values of a secret, newest first. Metadata only.</summary>
    Task<IReadOnlyList<SecretVersionDto>> ListVersionsAsync(Guid id, CancellationToken ct);

    /// <summary>Decrypts an archived version. Audit row is committed BEFORE any decryption (fail-closed).</summary>
    Task<RevealedSecretDto> RevealVersionAsync(Guid id, Guid versionId, CancellationToken ct);

    /// <summary>Reverts the secret's live value to an archived version (archiving the current value first). Audited.</summary>
    Task RestoreVersionAsync(Guid id, Guid versionId, CancellationToken ct);

    Task DeleteAsync(Guid id, CancellationToken ct);
}
