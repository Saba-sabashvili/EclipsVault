using EclipsVault.Core.Application.Abac;
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.DynamicSecrets;

/// <summary>
/// A role as offered to a caller — the recipe's shape, never its statements (those are backend
/// rights in text form). Implements <see cref="IAbacResource"/> so issuing is gated by the same
/// handler and rule engine as opening a stored secret.
/// </summary>
public sealed record DynamicSecretRoleDto(
    Guid Id,
    string Name,
    string Description,
    string ProjectKey,
    SecretEnvironment Environment,
    SensitivityLevel Sensitivity,
    DynamicSecretBackend Backend,
    int DefaultTtlMinutes,
    int MaxTtlMinutes,
    bool IsEnabled) : IAbacResource;

/// <summary>
/// A freshly minted credential. Exists only for the duration of the response that issued it — the
/// vault never stores <see cref="Secret"/>, so this is the one and only time it can be read.
/// </summary>
public sealed record IssuedCredentialDto(
    Guid LeaseId,
    string RoleName,
    string Identity,
    string Secret,
    DateTimeOffset ExpiresAtUtc);

/// <summary>A lease as shown in the UI. Carries no credential material.</summary>
public sealed record LeaseDto(
    Guid Id,
    Guid RoleId,
    string RoleName,
    string CredentialIdentity,
    string Username,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    DateTimeOffset? ClosedAtUtc,
    LeaseStatus Status,
    string? RevocationError);
