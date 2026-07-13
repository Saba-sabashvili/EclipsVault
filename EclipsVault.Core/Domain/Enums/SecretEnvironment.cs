namespace EclipsVault.Core.Domain.Enums;

/// <summary>Deployment environment a secret belongs to. Used as a resource attribute in ABAC evaluation.</summary>
public enum SecretEnvironment
{
    Development = 1,
    Staging = 2,
    Production = 3
}
