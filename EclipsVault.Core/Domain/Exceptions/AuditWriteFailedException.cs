namespace EclipsVault.Core.Domain.Exceptions;

/// <summary>
/// Raised when the audit trail cannot be persisted. The vault operates fail-closed:
/// if this is thrown, the surrounding operation has been aborted and no secret
/// material has been (or will be) released.
/// </summary>
public sealed class AuditWriteFailedException : DomainException
{
    public AuditWriteFailedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
