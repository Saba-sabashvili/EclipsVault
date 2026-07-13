using System.Security.Cryptography;
using System.Text;
using EclipsVault.Infrastructure.Security;
using Xunit;

namespace EclipsVault.Tests.Security;

/// <summary>
/// Envelope-encryption round-trips, plus the two rotation-critical invariants: a DEK is
/// unwrapped with whichever KEK sealed it, and a re-wrap moves the DEK to the current KEK
/// without touching (or needing to decrypt) the payload.
/// </summary>
public class AesGcmCryptoEngineTests
{
    /// <summary>In-memory KEK provider holding a current key plus any number of retired keys.</summary>
    private sealed class FakeKekProvider : IKekProvider
    {
        private readonly Dictionary<string, byte[]> _keys;

        public FakeKekProvider(string currentId, byte[] current, params (string id, byte[] key)[] retired)
        {
            CurrentKekId = currentId;
            CurrentKek = current;
            _keys = new Dictionary<string, byte[]>(StringComparer.Ordinal) { [currentId] = current };
            foreach (var (id, key) in retired)
            {
                _keys[id] = key;
            }
        }

        public string CurrentKekId { get; }
        public byte[] CurrentKek { get; }
        public IReadOnlyList<string> KnownKekIds => _keys.Keys.ToList();
        public byte[] ResolveKek(string kekId) => _keys[kekId];
    }

    private static AesGcmCryptoEngine Engine(string currentId, byte[] current, params (string, byte[])[] retired)
        => new(new FakeKekProvider(currentId, current, retired));

    private static byte[] Key() => RandomNumberGenerator.GetBytes(32);

    [Fact]
    public void Seal_then_unseal_recovers_the_plaintext()
    {
        var engine = Engine("kek-a", Key());
        var plaintext = Encoding.UTF8.GetBytes("Sup3r$ecretS4-Pr0d-2026!");

        var sealed_ = engine.Seal(plaintext);
        Assert.Equal(plaintext, engine.Unseal(sealed_));
    }

    [Fact]
    public void Each_seal_uses_a_fresh_dek_so_ciphertexts_differ()
    {
        var engine = Engine("kek-a", Key());
        var plaintext = Encoding.UTF8.GetBytes("same input");

        var first = engine.Seal(plaintext);
        var second = engine.Seal(plaintext);
        Assert.NotEqual(first.Ciphertext, second.Ciphertext);
    }

    [Fact]
    public void Unseal_uses_the_kek_that_sealed_the_secret_not_the_current_one()
    {
        var retired = Key();
        var sealed_ = Engine("kek-old", retired).Seal(Encoding.UTF8.GetBytes("legacy secret"));

        // A rotated engine: different current KEK, but it still holds the old one as retired.
        var rotated = Engine("kek-new", Key(), ("kek-old", retired));
        Assert.Equal("legacy secret", Encoding.UTF8.GetString(rotated.Unseal(sealed_)));
    }

    [Fact]
    public void Rewrap_moves_the_dek_to_the_current_kek_and_leaves_the_payload_byte_identical()
    {
        var oldKey = Key();
        var sealed_ = Engine("kek-old", oldKey).Seal(Encoding.UTF8.GetBytes("payload"));

        var rotated = Engine("kek-new", Key(), ("kek-old", oldKey));
        var rewrapped = rotated.Rewrap(sealed_);

        Assert.Equal("kek-new", rewrapped.KekId);
        Assert.Equal(sealed_.Ciphertext, rewrapped.Ciphertext);        // payload never re-encrypted
        Assert.NotEqual(sealed_.WrappedDek, rewrapped.WrappedDek);     // DEK re-wrapped
        Assert.Equal("payload", Encoding.UTF8.GetString(rotated.Unseal(rewrapped)));
    }

    [Fact]
    public void Rewrap_is_a_noop_when_already_under_the_current_kek()
    {
        var engine = Engine("kek-a", Key());
        var sealed_ = engine.Seal(Encoding.UTF8.GetBytes("x"));
        Assert.Same(sealed_, engine.Rewrap(sealed_));
    }

    [Fact]
    public void Tampering_with_the_ciphertext_is_detected_by_the_gcm_tag()
    {
        var engine = Engine("kek-a", Key());
        var sealed_ = engine.Seal(Encoding.UTF8.GetBytes("secret"));
        sealed_.Ciphertext[^1] ^= 0xFF;

        Assert.Throws<AuthenticationTagMismatchException>(() => engine.Unseal(sealed_));
    }
}
