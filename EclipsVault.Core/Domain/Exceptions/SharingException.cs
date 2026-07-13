namespace EclipsVault.Core.Domain.Exceptions;

/// <summary>Raised when a secret-sharing operation is invalid (unknown grantee, duplicate grant, sharing with yourself). The message is safe to show the user.</summary>
public sealed class SharingException : DomainException
{
    public SharingException(string message) : base(message)
    {
    }
}
