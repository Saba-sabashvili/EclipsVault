namespace EclipsVault.Core.Domain.Exceptions;

/// <summary>
/// Raised when a self-service profile operation is invalid (wrong current password,
/// weak new password, unreadable image, …). The message is safe to show the user.
/// </summary>
public sealed class ProfileException : DomainException
{
    public ProfileException(string message) : base(message)
    {
    }
}
