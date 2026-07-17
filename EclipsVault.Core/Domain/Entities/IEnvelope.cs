namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// The four columns that carry an envelope-encrypted payload — the ciphertext, the DEK wrapped by the
/// master KEK, the id of that KEK, and the algorithm tag. Shared by <see cref="Secret"/>,
/// <see cref="SecretVersion"/>, and the cache DTO so the mapping to and from a <c>SealedSecret</c>
/// lives in exactly one place (see <c>EnvelopeMapping</c>). Read-only here;
/// <see cref="IMutableEnvelope"/> adds the setters the entities need to be re-sealed in place.
/// </summary>
public interface IEnvelope
{
    byte[] Ciphertext { get; }
    byte[] WrappedDek { get; }
    string KekId { get; }
    string Algorithm { get; }
}

/// <summary>
/// An <see cref="IEnvelope"/> whose columns can be written — the mutable entities. Exists so a
/// re-seal, rotation, or restore writes all four fields through one call rather than four
/// hand-copied lines, where copying three and forgetting the fourth would silently corrupt a secret.
/// </summary>
public interface IMutableEnvelope : IEnvelope
{
    new byte[] Ciphertext { get; set; }
    new byte[] WrappedDek { get; set; }
    new string KekId { get; set; }
    new string Algorithm { get; set; }
}
