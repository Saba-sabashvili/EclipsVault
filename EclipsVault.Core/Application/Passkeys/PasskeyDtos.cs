namespace EclipsVault.Core.Application.Passkeys;

/// <summary>
/// The output of a "begin" ceremony: <see cref="OptionsJson"/> is the JSON handed to the
/// browser (fed to <c>navigator.credentials</c>), while <see cref="Challenge"/> (base64url)
/// is stashed server-side and handed back to the matching "complete" call so the response
/// can be verified against the exact challenge that was issued.
/// </summary>
public sealed record PasskeyCeremonyOptions(string OptionsJson, string Challenge);

/// <summary>Outcome of a WebAuthn registration ceremony.</summary>
public sealed record PasskeyRegistrationResult(bool Success, string? Error)
{
    public static readonly PasskeyRegistrationResult Ok = new(true, null);

    public static PasskeyRegistrationResult Failed(string error) => new(false, error);
}

/// <summary>
/// Outcome of a WebAuthn assertion (passwordless sign-in) ceremony. On success the resolved
/// user is returned so the Web layer can issue the full session, exactly as it does after TOTP.
/// </summary>
public sealed record PasskeyAssertionResult(bool Success, string? Error, UserDto? User)
{
    public static PasskeyAssertionResult Failed(string error) => new(false, error, null);

    public static PasskeyAssertionResult Succeeded(UserDto user) => new(true, null, user);
}

/// <summary>A registered passkey as shown in the self-service profile list.</summary>
public sealed record PasskeySummary(Guid Id, string Nickname, DateTimeOffset CreatedAtUtc);
