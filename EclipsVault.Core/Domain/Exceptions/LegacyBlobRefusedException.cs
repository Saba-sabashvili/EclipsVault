namespace EclipsVault.Core.Domain.Exceptions;

/// <summary>
/// Raised when a stored payload is sealed in the pre-binding format and the vault is configured to
/// refuse those (the default). This is <em>not</em> a broken subsystem — the crypto is working — so
/// it is deliberately distinct from <see cref="CryptoConfigurationException"/>: it is a fail-closed
/// refusal to read an envelope that cannot be proven to belong to its row, pending the one-time
/// re-seal migration. It therefore maps to a clean "refused" outcome rather than a 500, and nothing
/// is decrypted.
/// </summary>
public sealed class LegacyBlobRefusedException : DomainException
{
    public LegacyBlobRefusedException(string message) : base(message)
    {
    }
}
