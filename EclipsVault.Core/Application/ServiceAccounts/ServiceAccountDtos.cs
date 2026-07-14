using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.ServiceAccounts;

public sealed record ServiceAccountSummaryDto(
    Guid Id,
    string Name,
    ClearanceLevel Clearance,
    string ProjectKey,
    bool IsDisabled,
    int ActiveKeyCount,
    DateTimeOffset CreatedAtUtc);

public sealed record ApiKeyDto(
    Guid Id,
    string Prefix,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    DateTimeOffset? RevokedAtUtc,
    DateTimeOffset? LastUsedAtUtc,
    ClearanceLevel? ClearanceCeiling,
    string? ProjectScope,
    bool MetadataOnly,
    IReadOnlyList<string> AllowedCidrs)
{
    /// <summary>True when the key narrows access below its service account in any dimension.</summary>
    public bool IsScoped => ClearanceCeiling is not null || !string.IsNullOrEmpty(ProjectScope) || MetadataOnly || AllowedCidrs.Count > 0;
}

public sealed record ServiceAccountDetailsDto(
    Guid Id,
    string Name,
    ClearanceLevel Clearance,
    string ProjectKey,
    bool IsDisabled,
    DateTimeOffset CreatedAtUtc,
    IReadOnlyList<ApiKeyDto> Keys);

public sealed record CreateServiceAccountRequest(string Name, ClearanceLevel Clearance, string ProjectKey);

/// <summary>
/// Options for issuing a key. Every field only narrows the key below its account:
/// a lower clearance ceiling, a single permitted project, and/or metadata-only access.
/// </summary>
public sealed record IssueApiKeyRequest(
    int? TtlDays,
    ClearanceLevel? ClearanceCeiling,
    string? ProjectScope,
    bool MetadataOnly,
    IReadOnlyList<string>? AllowedCidrs = null);

/// <summary>Returned once, at issue time — carries the raw token, which is never persisted or shown again.</summary>
public sealed record IssuedApiKeyDto(Guid Id, string RawToken, string Prefix);

/// <summary>
/// The identity resolved from a valid API key, used to build the API caller's principal.
/// <see cref="Clearance"/> is the key's <em>effective</em> clearance (account capped by any
/// ceiling); <see cref="ProjectScope"/> and <see cref="MetadataOnly"/> carry the remaining scope.
/// </summary>
public sealed record AuthenticatedServiceAccount(
    Guid Id,
    string Name,
    ClearanceLevel Clearance,
    string ProjectKey,
    string? ProjectScope,
    bool MetadataOnly);
