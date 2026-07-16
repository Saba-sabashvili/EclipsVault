using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Secrets;

/// <summary>List row. Carries attribute metadata only — no cryptographic material.
/// The honey-token flag is surfaced so the UI can warn high-clearance staff; it must
/// never be rendered to ordinary users.</summary>
public sealed record SecretSummaryDto(
    Guid Id,
    string Name,
    string ProjectKey,
    SecretEnvironment Environment,
    SensitivityLevel Sensitivity,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    bool IsHoneyToken);

/// <summary>Detail view and the resource evaluated by the ABAC authorization handler.</summary>
public sealed record SecretDetailsDto(
    Guid Id,
    string Name,
    string ProjectKey,
    SecretEnvironment Environment,
    SensitivityLevel Sensitivity,
    string Algorithm,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? UpdatedAtUtc,
    DateTimeOffset? ExpiresAtUtc) : IAbacResource;

/// <summary>A decrypted payload. Exists only for the duration of a single authorized response.</summary>
public sealed record RevealedSecretDto(Guid Id, string Name, string Value);

/// <summary>One archived (superseded) value of a secret. Metadata only — no key material.</summary>
public sealed record SecretVersionDto(
    Guid Id,
    int VersionNumber,
    DateTimeOffset ArchivedAtUtc,
    string ArchivedBy,
    string? ChangeNote);

public sealed record CreateSecretRequest(
    string Name,
    string Value,
    string ProjectKey,
    SecretEnvironment Environment,
    SensitivityLevel Sensitivity,
    int TtlDays);
