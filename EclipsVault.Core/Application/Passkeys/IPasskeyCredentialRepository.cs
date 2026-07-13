using EclipsVault.Core.Domain.Entities;

namespace EclipsVault.Core.Application.Passkeys;

/// <summary>Persistence port for WebAuthn credentials. Owns the <see cref="PasskeyCredential"/> aggregate only.</summary>
public interface IPasskeyCredentialRepository
{
    Task AddAsync(PasskeyCredential credential, CancellationToken ct);

    /// <summary>Looks up a credential by its authenticator-issued id (unique). Tracked, so the sign counter can be updated.</summary>
    Task<PasskeyCredential?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken ct);

    Task<IReadOnlyList<PasskeyCredential>> ListForUserAsync(Guid userId, CancellationToken ct);

    /// <summary>Loads one of the user's own credentials — scoped by user id so a caller can only touch their own passkeys.</summary>
    Task<PasskeyCredential?> FindByIdForUserAsync(Guid id, Guid userId, CancellationToken ct);

    Task UpdateAsync(PasskeyCredential credential, CancellationToken ct);

    Task DeleteAsync(PasskeyCredential credential, CancellationToken ct);
}
