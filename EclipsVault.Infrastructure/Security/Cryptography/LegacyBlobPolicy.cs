using EclipsVault.Core.Domain.Exceptions;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Decides what binding a stored payload is checked against, and refuses the unbound ones unless an
/// operator has explicitly opened the door for a migration.
///
/// Shared by both engines so they cannot drift on whether an unbound blob is acceptable — a
/// disagreement there would mean the answer to "may this envelope be read out of its row?" depends
/// on which engine is configured.
/// </summary>
internal static class LegacyBlobPolicy
{
    public static ReadOnlySpan<byte> BindingFor(string algorithm, byte[] associatedData, CryptoOptions options)
    {
        if (SealAlgorithms.IsBound(algorithm))
        {
            return associatedData;
        }

        if (!options.AllowUnauthenticatedLegacyBlobs)
        {
            throw new CryptoConfigurationException(
                $"This secret is sealed with '{algorithm}', which predates binding a payload to its row, so " +
                "nothing proves this envelope belongs where it is stored. Reading it is refused. Set " +
                "Crypto:AllowUnauthenticatedLegacyBlobs=true to re-seal the vault's existing secrets on the " +
                "next start, then turn it back off — while it is on, the binding can be bypassed by anyone " +
                "who can write the database.");
        }

        return default; // sealed before binding existed: there is nothing to check it against
    }
}
