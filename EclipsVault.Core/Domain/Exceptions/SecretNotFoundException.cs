namespace EclipsVault.Core.Domain.Exceptions;

/// <summary>Raised when a secret does not exist, is expired, or has been shredded.</summary>
public sealed class SecretNotFoundException : DomainException
{
    public Guid SecretId { get; }

    public SecretNotFoundException(Guid secretId)
        : base($"Secret '{secretId}' was not found.")
    {
        SecretId = secretId;
    }
}
