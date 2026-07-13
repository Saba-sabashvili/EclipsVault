namespace EclipsVault.Core.Domain.Exceptions;

/// <summary>
/// Raised when an administrative operation is invalid (duplicate username, deleting
/// yourself, malformed CIDR, …). The message is safe to show to the administrator.
/// </summary>
public sealed class VaultAdminException : DomainException
{
    public VaultAdminException(string message) : base(message)
    {
    }
}
