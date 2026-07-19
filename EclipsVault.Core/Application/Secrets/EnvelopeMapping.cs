using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Domain.Entities;

namespace EclipsVault.Core.Application.Secrets;

/// <summary>
/// The one place the four envelope columns cross to and from a <see cref="SealedSecret"/>. Every
/// reveal, rotation, restore, and legacy re-seal used to construct or copy these four fields by hand;
/// a single mapper means adding a fifth column is one edit rather than a hunt across the codebase,
/// and no site can copy three of four and quietly drop the fourth.
/// </summary>
public static class EnvelopeMapping
{
    /// <summary>Reads the four envelope columns off any carrier into a <see cref="SealedSecret"/>.</summary>
    public static SealedSecret ToSealedSecret(this IEnvelope envelope)
        => new(envelope.Ciphertext, envelope.WrappedDek, envelope.KekId, envelope.Algorithm);

    /// <summary>
    /// Writes a <see cref="SealedSecret"/>'s four columns back onto a mutable carrier atomically, so a
    /// re-seal cannot land three fields and leave the fourth stale.
    /// </summary>
    public static void ApplyEnvelope(this IMutableEnvelope target, SealedSecret sealedSecret)
    {
        target.Ciphertext = sealedSecret.Ciphertext;
        target.WrappedDek = sealedSecret.WrappedDek;
        target.KekId = sealedSecret.KekId;
        target.Algorithm = sealedSecret.Algorithm;
    }
}
