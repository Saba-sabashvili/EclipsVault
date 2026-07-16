using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Abac;

/// <summary>
/// Anything the ABAC engine can gate: it carries the three resource attributes
/// <see cref="SecretAccessPolicy"/> reads. Implemented by a stored secret's details and by a
/// dynamic-secret role, so both are decided by one handler and one rule engine — a second copy of
/// "who may reach this?" is exactly the drift this codebase keeps out of the access path.
/// </summary>
public interface IAbacResource
{
    Guid Id { get; }

    string Name { get; }

    string ProjectKey { get; }

    SecretEnvironment Environment { get; }

    SensitivityLevel Sensitivity { get; }
}
