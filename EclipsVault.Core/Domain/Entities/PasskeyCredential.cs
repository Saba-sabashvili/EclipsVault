namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// A WebAuthn/passkey credential registered by a user. Persistence is wired up so the
/// FIDO2 ceremony layer (see IPasskeyService) can be plugged in without schema changes.
/// </summary>
public class PasskeyCredential
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public User? User { get; set; }

    /// <summary>Raw credential id returned by the authenticator.</summary>
    public byte[] CredentialId { get; set; } = [];

    /// <summary>COSE-encoded public key.</summary>
    public byte[] PublicKey { get; set; } = [];

    /// <summary>Signature counter used for clone detection.</summary>
    public long SignCount { get; set; }

    public string? Nickname { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }
}
