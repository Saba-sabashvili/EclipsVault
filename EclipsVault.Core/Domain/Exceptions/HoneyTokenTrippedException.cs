namespace EclipsVault.Core.Domain.Exceptions;

/// <summary>
/// Raised after a honey-token decoy was requested by id. By the time this surfaces,
/// the intrusion response (session revocation, IP-range blacklisting, critical alert)
/// has already executed.
/// </summary>
public sealed class HoneyTokenTrippedException : DomainException
{
    public Guid SecretId { get; }

    public string SecretName { get; }

    public HoneyTokenTrippedException(Guid secretId, string secretName)
        : base($"Honey-token '{secretName}' was requested. Intrusion response has been executed.")
    {
        SecretId = secretId;
        SecretName = secretName;
    }
}
