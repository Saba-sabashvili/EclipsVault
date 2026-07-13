namespace EclipsVault.Core.Domain.Exceptions;

/// <summary>Raised when the cryptographic subsystem is misconfigured (missing/invalid KEK, unknown engine).</summary>
public sealed class CryptoConfigurationException : DomainException
{
    public CryptoConfigurationException(string message) : base(message)
    {
    }
}
