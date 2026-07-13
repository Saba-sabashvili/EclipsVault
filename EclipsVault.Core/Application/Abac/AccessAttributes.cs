using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Abac;

/// <summary>Subject attributes extracted from the authenticated principal's claims.</summary>
public sealed record SubjectAttributes(ClearanceLevel Clearance, string ProjectKey);

/// <summary>
/// Extra constraints an API key places on itself, narrowing access below its service
/// account's attributes. Absent (null) for interactive users, who carry no scope.
/// </summary>
public sealed record ApiKeyScope(string? ProjectScope, bool MetadataOnly);

/// <summary>Resource attributes of the secret being evaluated.</summary>
public sealed record ResourceAttributes(SecretEnvironment Environment, SensitivityLevel Sensitivity, string ProjectKey);

/// <summary>
/// Runtime context of the request. The host computes the environmental facts
/// (time window, network trust) so this layer stays a pure, testable rule engine.
/// </summary>
public sealed record RequestContext(
    DateTimeOffset UtcNow,
    string? SourceIp,
    bool IsWithinProductionWindow,
    bool IsFromTrustedNetwork,
    bool IsExplicitlyGranted = false);

/// <summary>Outcome of an ABAC evaluation, including every reason a denial occurred.</summary>
public sealed record AccessDecision(bool IsAllowed, IReadOnlyList<string> DenialReasons)
{
    public static AccessDecision Allow() => new(true, []);

    public static AccessDecision Deny(IReadOnlyList<string> reasons) => new(false, reasons);
}
