namespace EclipsVault.Core.Application.Abstractions;

public sealed record PasswordHashResult(byte[] Hash, byte[] Salt);

/// <summary>Argon2id password hashing with a unique cryptographically-random salt per user.</summary>
public interface IPasswordHasher
{
    PasswordHashResult Hash(string password);

    bool Verify(string password, byte[] hash, byte[] salt);
}
