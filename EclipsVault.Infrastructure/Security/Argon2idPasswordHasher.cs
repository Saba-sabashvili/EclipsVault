using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Security;

public sealed class Argon2Options
{
    public const string SectionName = "Argon2";

    /// <summary>Number of passes over memory.</summary>
    public int Iterations { get; set; } = 3;

    /// <summary>Memory cost in KiB (65536 = 64 MiB).</summary>
    public int MemoryKb { get; set; } = 65536;

    /// <summary>Degree of parallelism (lanes).</summary>
    public int Parallelism { get; set; } = 4;
}

/// <summary>
/// Argon2id hashing with a unique, cryptographically random 16-byte salt per user.
/// Verification is constant-time.
/// </summary>
public sealed class Argon2idPasswordHasher : IPasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;

    private readonly Argon2Options _options;

    public Argon2idPasswordHasher(IOptions<Argon2Options> options) => _options = options.Value;

    public PasswordHashResult Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        return new PasswordHashResult(ComputeHash(password, salt), salt);
    }

    public bool Verify(string password, byte[] hash, byte[] salt)
        => CryptographicOperations.FixedTimeEquals(ComputeHash(password, salt), hash);

    private byte[] ComputeHash(string password, byte[] salt)
    {
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = _options.Parallelism,
            Iterations = _options.Iterations,
            MemorySize = _options.MemoryKb
        };
        return argon2.GetBytes(HashSize);
    }
}
