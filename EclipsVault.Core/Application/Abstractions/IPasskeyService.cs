namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Drives the WebAuthn/passkey ceremonies for passwordless multi-factor sign-in. The
/// implementation lives in Infrastructure (the FIDO2 relying-party logic) so the domain
/// layer stays free of any crypto or wire-format concern; it traffics only in JSON strings
/// and Core DTOs. Ceremony state (the issued challenge) is carried by the Web layer between
/// each "begin"/"complete" pair, keeping this service stateless.
/// </summary>
public interface IPasskeyService
{
    /// <summary>Issues creation options for the signed-in user to register a new authenticator.</summary>
    Task<PasskeyCeremonyOptions> BeginRegistrationAsync(Guid userId, CancellationToken ct);

    /// <summary>Verifies the authenticator's attestation response and stores the new credential.</summary>
    Task<PasskeyRegistrationResult> CompleteRegistrationAsync(
        Guid userId, string expectedChallenge, string responseJson, string? nickname, CancellationToken ct);

    /// <summary>Issues assertion options for a passwordless sign-in. A username scopes the allowed credentials; null enables discoverable credentials.</summary>
    Task<PasskeyCeremonyOptions> BeginAssertionAsync(string? usernameOrEmail, CancellationToken ct);

    /// <summary>Verifies an assertion response and, on success, returns the authenticated user.</summary>
    Task<PasskeyAssertionResult> CompleteAssertionAsync(string expectedChallenge, string responseJson, CancellationToken ct);

    /// <summary>Lists the caller's registered passkeys for the profile page.</summary>
    Task<IReadOnlyList<PasskeySummary>> ListForUserAsync(Guid userId, CancellationToken ct);

    /// <summary>Removes one of the caller's own passkeys. Returns false if it was not found.</summary>
    Task<bool> RemoveAsync(Guid userId, Guid passkeyId, CancellationToken ct);
}
