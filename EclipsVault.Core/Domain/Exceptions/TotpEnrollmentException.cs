namespace EclipsVault.Core.Domain.Exceptions;

/// <summary>Raised when a TOTP enrollment step is attempted in an invalid state.</summary>
public sealed class TotpEnrollmentException : DomainException
{
    public TotpEnrollmentException(string message) : base(message)
    {
    }
}
