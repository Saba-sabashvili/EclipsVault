using EclipsVault.Core.Domain.Entities;

namespace EclipsVault.Core.Application.Mfa;

/// <summary>Persistence for a user's single-use MFA recovery codes.</summary>
public interface IMfaRecoveryCodeRepository
{
    /// <summary>Unused codes for a user, oldest first.</summary>
    Task<IReadOnlyList<MfaRecoveryCode>> ListUnusedAsync(Guid userId, CancellationToken ct);

    Task<int> CountUnusedAsync(Guid userId, CancellationToken ct);

    /// <summary>Deletes every code the user currently holds and inserts the new set in one transaction.</summary>
    Task ReplaceAllAsync(Guid userId, IReadOnlyList<MfaRecoveryCode> codes, CancellationToken ct);

    /// <summary>Persists a single code as consumed (its <see cref="MfaRecoveryCode.UsedAtUtc"/> is already set).</summary>
    Task MarkUsedAsync(MfaRecoveryCode code, CancellationToken ct);

    /// <summary>Removes every code for the user — used when their authenticator is reset.</summary>
    Task DeleteAllAsync(Guid userId, CancellationToken ct);
}
