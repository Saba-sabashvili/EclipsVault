namespace EclipsVault.Core.Domain.Exceptions;

/// <summary>Base type for every exception raised by the vault's domain and application layers.</summary>
public abstract class DomainException : Exception
{
    protected DomainException(string message) : base(message)
    {
    }

    protected DomainException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
