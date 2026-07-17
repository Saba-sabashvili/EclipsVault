using System.Security.Cryptography;
using System.Text;
using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Domain.Exceptions;
using EclipsVault.Infrastructure.Security;
using Microsoft.Extensions.Options;
using Xunit;

namespace EclipsVault.Tests.Security;

/// <summary>
/// Envelope-encryption round-trips, plus the two rotation-critical invariants: a DEK is
/// unwrapped with whichever KEK sealed it, and a re-wrap moves the DEK to the current KEK
/// without touching (or needing to decrypt) the payload.
///
/// And the property those alone never gave: a sealed payload is only decryptable in the row it was
/// sealed for. GCM proves a blob was not edited but says nothing about where it came from, so
/// without a binding anyone who could write the database could lift a production secret's envelope
/// into a development row they were cleared to read, and the vault would hand back the plaintext.
/// </summary>
public class AesGcmCryptoEngineTests
{
    private static readonly Guid SecretA = Guid.Parse("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa");
    private static readonly Guid SecretB = Guid.Parse("bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb");

    private static byte[] BindingA => SecretBinding.ForCurrentValue(SecretA);
    private static byte[] BindingB => SecretBinding.ForCurrentValue(SecretB);
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
        => Engine(new CryptoOptions(), currentId, current, retired);

    private static AesGcmCryptoEngine Engine(
        CryptoOptions options, string currentId, byte[] current, params (string, byte[])[] retired)
        => new(new FakeKekProvider(currentId, current, retired), Options.Create(options));

    private static byte[] Key() => RandomNumberGenerator.GetBytes(32);

    [Fact]
    public void Seal_then_unseal_recovers_the_plaintext()
    {
        var engine = Engine("kek-a", Key());
        var plaintext = Encoding.UTF8.GetBytes("Sup3r$ecretS4-Pr0d-2026!");

        var sealed_ = engine.Seal(plaintext, BindingA);
        Assert.Equal(plaintext, engine.Unseal(sealed_, BindingA));
    }

    [Fact]
    public void Each_seal_uses_a_fresh_dek_so_ciphertexts_differ()
    {
        var engine = Engine("kek-a", Key());
        var plaintext = Encoding.UTF8.GetBytes("same input");

        var first = engine.Seal(plaintext, BindingA);
        var second = engine.Seal(plaintext, BindingA);
        Assert.NotEqual(first.Ciphertext, second.Ciphertext);
    }

    [Fact]
    public void Unseal_uses_the_kek_that_sealed_the_secret_not_the_current_one()
    {
        var retired = Key();
        var sealed_ = Engine("kek-old", retired).Seal(Encoding.UTF8.GetBytes("legacy secret"), BindingA);

        // A rotated engine: different current KEK, but it still holds the old one as retired.
        var rotated = Engine("kek-new", Key(), ("kek-old", retired));
        Assert.Equal("legacy secret", Encoding.UTF8.GetString(rotated.Unseal(sealed_, BindingA)));
    }

    [Fact]
    public void Rewrap_moves_the_dek_to_the_current_kek_and_leaves_the_payload_byte_identical()
    {
        var oldKey = Key();
        var sealed_ = Engine("kek-old", oldKey).Seal(Encoding.UTF8.GetBytes("payload"), BindingA);

        var rotated = Engine("kek-new", Key(), ("kek-old", oldKey));
        var rewrapped = rotated.Rewrap(sealed_);

        Assert.Equal("kek-new", rewrapped.KekId);
        Assert.Equal(sealed_.Ciphertext, rewrapped.Ciphertext);        // payload never re-encrypted
        Assert.NotEqual(sealed_.WrappedDek, rewrapped.WrappedDek);     // DEK re-wrapped
        Assert.Equal("payload", Encoding.UTF8.GetString(rotated.Unseal(rewrapped, BindingA)));
    }

    [Fact]
    public void Rewrap_is_a_noop_when_already_under_the_current_kek()
    {
        var engine = Engine("kek-a", Key());
        var sealed_ = engine.Seal(Encoding.UTF8.GetBytes("x"), BindingA);
        Assert.Same(sealed_, engine.Rewrap(sealed_));
    }

    [Fact]
    public void Tampering_with_the_ciphertext_is_detected_by_the_gcm_tag()
    {
        var engine = Engine("kek-a", Key());
        var sealed_ = engine.Seal(Encoding.UTF8.GetBytes("secret"), BindingA);
        sealed_.Ciphertext[^1] ^= 0xFF;

        Assert.Throws<AuthenticationTagMismatchException>(() => engine.Unseal(sealed_, BindingA));
    }

    // ---- an envelope only decrypts in the row it belongs to -------------------------------

    [Fact]
    public void A_whole_envelope_moved_onto_another_secret_will_not_decrypt_there()
    {
        // The attack this exists to stop, and it needs nothing but one UPDATE: copy the
        // ciphertext, wrapped DEK, key id and algorithm of a secret you cannot read onto one you
        // can, then read it through the front door.
        var engine = Engine("kek-a", Key());
        var stolen = engine.Seal(Encoding.UTF8.GetBytes("prod-root-key"), BindingA);

        Assert.Throws<AuthenticationTagMismatchException>(() => engine.Unseal(stolen, BindingB));
    }

    [Fact]
    public void An_archived_version_cannot_be_promoted_to_the_live_value()
    {
        // The same move backwards: put a rotated-away credential back as the current one, without
        // the restore that would have been audited and access-controlled.
        var engine = Engine("kek-a", Key());
        var versionId = Guid.NewGuid();
        var archived = engine.Seal(
            Encoding.UTF8.GetBytes("the password we rotated away from"),
            SecretBinding.ForArchivedVersion(SecretA, versionId));

        Assert.Throws<AuthenticationTagMismatchException>(() => engine.Unseal(archived, BindingA));
    }

    [Fact]
    public void A_version_cannot_be_moved_to_another_version_of_the_same_secret()
    {
        var engine = Engine("kek-a", Key());
        var sealed_ = engine.Seal(Encoding.UTF8.GetBytes("v1"), SecretBinding.ForArchivedVersion(SecretA, Guid.NewGuid()));

        Assert.Throws<AuthenticationTagMismatchException>(
            () => engine.Unseal(sealed_, SecretBinding.ForArchivedVersion(SecretA, Guid.NewGuid())));
    }

    [Fact]
    public void A_version_cannot_be_moved_under_a_different_parent_secret()
    {
        var engine = Engine("kek-a", Key());
        var versionId = Guid.NewGuid();
        var sealed_ = engine.Seal(Encoding.UTF8.GetBytes("v1"), SecretBinding.ForArchivedVersion(SecretA, versionId));

        Assert.Throws<AuthenticationTagMismatchException>(
            () => engine.Unseal(sealed_, SecretBinding.ForArchivedVersion(SecretB, versionId)));
    }

    [Fact]
    public void Seal_records_that_the_payload_is_bound()
    {
        var sealed_ = Engine("kek-a", Key()).Seal(Encoding.UTF8.GetBytes("x"), BindingA);
        Assert.Equal("AES-256-GCM-AAD", sealed_.Algorithm);
    }

    // ---- the unbound blobs of an older vault ----------------------------------------------

    /// <summary>An envelope as it was written before payloads were bound to their row.</summary>
    private static SealedSecret LegacyBlob(AesGcmCryptoEngine engine, string value)
        => engine.Seal(Encoding.UTF8.GetBytes(value), []) with { Algorithm = "AES-256-GCM" };

    [Fact]
    public void A_legacy_blob_is_refused_by_default()
    {
        // Algorithm sits unauthenticated next to the ciphertext, so if the row could ask to be read
        // the old way, anyone who can write the row can ask for it — and the binding is decoration.
        var engine = Engine("kek-a", Key());
        var legacy = LegacyBlob(engine, "old secret");

        var ex = Assert.Throws<LegacyBlobRefusedException>(() => engine.Unseal(legacy, BindingA));
        Assert.Contains("AllowUnauthenticatedLegacyBlobs", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_legacy_blob_is_readable_only_while_an_operator_is_migrating()
    {
        var options = new CryptoOptions { AllowUnauthenticatedLegacyBlobs = true };
        var key = Key();
        var legacy = LegacyBlob(Engine(options, "kek-a", key), "old secret");

        var engine = Engine(options, "kek-a", key);
        Assert.Equal("old secret", Encoding.UTF8.GetString(engine.Unseal(legacy, BindingA)));
    }

    [Fact]
    public void The_downgrade_is_shut_once_the_migration_switch_is_off()
    {
        // Relabelling a bound blob as legacy must not make it readable out of its row.
        var key = Key();
        var bound = Engine("kek-a", key).Seal(Encoding.UTF8.GetBytes("prod-root-key"), BindingA);
        var relabelled = bound with { Algorithm = "AES-256-GCM" };

        Assert.Throws<LegacyBlobRefusedException>(() => Engine("kek-a", key).Unseal(relabelled, BindingB));
    }

    [Fact]
    public void Relabelling_a_bound_blob_as_legacy_does_not_reopen_the_substitution_even_while_migrating()
    {
        // The residual risk of the migration window is bounded: with the switch on, a bound blob
        // claiming to be legacy is checked against no binding — so it still fails, because it was
        // sealed with one.
        var options = new CryptoOptions { AllowUnauthenticatedLegacyBlobs = true };
        var key = Key();
        var bound = Engine(options, "kek-a", key).Seal(Encoding.UTF8.GetBytes("prod-root-key"), BindingA);
        var relabelled = bound with { Algorithm = "AES-256-GCM" };

        Assert.Throws<AuthenticationTagMismatchException>(
            () => Engine(options, "kek-a", key).Unseal(relabelled, BindingB));
    }
}
