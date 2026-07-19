using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Secrets;

/// <summary>A live grant on one secret, as shown in that secret's sharing panel.</summary>
public sealed record SecretGrantDto(
    Guid Id,
    Guid GranteeUserId,
    string GranteeUsername,
    string GrantedBy,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc);

/// <summary>A secret that has been shared with the current user, for the "Shared with me" page.</summary>
public sealed record SharedSecretDto(
    Guid SecretId,
    string Name,
    string ProjectKey,
    SecretEnvironment Environment,
    SensitivityLevel Sensitivity,
    string GrantedBy,
    DateTimeOffset? ExpiresAtUtc);

/// <summary>A grant the current user has handed out, for the "Shared by me" access-review page.</summary>
public sealed record OutgoingShareDto(
    Guid GrantId,
    Guid SecretId,
    string SecretName,
    string GranteeUsername,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc);

/// <summary>
/// Explicit per-user access grants on secrets. Consulted by the ABAC handler (to let
/// a grant satisfy the project rule) and drives the sharing panel and "Shared with me".
/// Every grant and revocation is audited.
/// </summary>
public interface ISecretGrantService
{
    /// <summary>True when an unexpired grant exists for this user on this secret (used by ABAC).</summary>
    Task<bool> HasActiveGrantAsync(Guid userId, Guid secretId, CancellationToken ct);

    Task<IReadOnlyList<SecretGrantDto>> ListForSecretAsync(Guid secretId, CancellationToken ct);

    Task<IReadOnlyList<SharedSecretDto>> ListSharedWithUserAsync(Guid userId, CancellationToken ct);

    /// <summary>Active grants this user has issued to others, across every secret — the "Shared by me" review.</summary>
    Task<IReadOnlyList<OutgoingShareDto>> ListIssuedByAsync(string grantorUsername, CancellationToken ct);

    /// <summary>Grants a user (by username or email) access to a secret. Throws SharingException on invalid input.</summary>
    Task GrantAsync(Guid secretId, string secretName, string granteeUsernameOrEmail, int? ttlDays, CancellationToken ct);

    Task<bool> RevokeAsync(Guid grantId, CancellationToken ct);

    /// <summary>
    /// Revokes a grant only if the caller is the one who issued it. Returns false when the grant is
    /// gone or was issued by someone else — so a caller can never revoke a grant that isn't theirs,
    /// and the two cases are indistinguishable to avoid leaking whether a grant id exists.
    /// </summary>
    Task<bool> RevokeIssuedAsync(Guid grantId, string grantorUsername, CancellationToken ct);
}
