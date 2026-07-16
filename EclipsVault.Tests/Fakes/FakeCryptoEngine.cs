using System.Security.Cryptography;
using EclipsVault.Core.Application.Abstractions;

namespace EclipsVault.Tests.Fakes;

/// <summary>
/// An identity seal that still enforces the binding: the payload is framed as
/// <c>len(aad) | aad | plaintext</c>, and unsealing under a different binding throws exactly as real
/// AES-GCM would.
///
/// It would be far easier to ignore the associated data here, and that is the trap: every test
/// would then pass whether or not the service bound a payload to the right row, which is the only
/// thing the binding is for. Tests share this one engine so no test class can quietly opt out.
/// </summary>
public sealed class FakeCryptoEngine : ICryptoEngine, ICryptoEngineFactory
{
    public string EngineId => "fake";

    public ICryptoEngine Create() => this;

    public SealedSecret Seal(byte[] plaintext, byte[] associatedData)
        => new(Frame(associatedData, plaintext), [], "test-kek", "FAKE");

    public byte[] Unseal(SealedSecret sealedSecret, byte[] associatedData)
    {
        var length = BitConverter.ToInt32(sealedSecret.Ciphertext, 0);
        var bound = sealedSecret.Ciphertext.AsSpan(sizeof(int), length);

        if (!bound.SequenceEqual(associatedData))
        {
            throw new AuthenticationTagMismatchException(
                "This payload is bound to a different row than the one it was read from.");
        }

        return sealedSecret.Ciphertext[(sizeof(int) + length)..];
    }

    public SealedSecret Rewrap(SealedSecret sealedSecret) => sealedSecret;

    /// <summary>The plaintext inside a framed ciphertext, for tests that assert on stored bytes.</summary>
    public static byte[] ValueOf(byte[] ciphertext)
        => ciphertext[(sizeof(int) + BitConverter.ToInt32(ciphertext, 0))..];

    private static byte[] Frame(byte[] associatedData, byte[] plaintext)
    {
        var framed = new byte[sizeof(int) + associatedData.Length + plaintext.Length];
        BitConverter.TryWriteBytes(framed, associatedData.Length);
        associatedData.CopyTo(framed, sizeof(int));
        plaintext.CopyTo(framed, sizeof(int) + associatedData.Length);
        return framed;
    }
}
