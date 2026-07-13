using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Authentication;

public sealed record UserDto(
    Guid Id,
    string Username,
    string DisplayName,
    string Email,
    ClearanceLevel Clearance,
    string ProjectKey,
    bool TotpEnabled,
    bool IsDisabled);

public enum CredentialStatus
{
    Invalid = 0,
    RequiresTotp = 1,
    RequiresTotpEnrollment = 2
}

public sealed record CredentialCheckResult(CredentialStatus Status, UserDto? User)
{
    public static readonly CredentialCheckResult Invalid = new(CredentialStatus.Invalid, null);
}

public sealed record TotpEnrollmentDto(string SecretBase32, string OtpAuthUri);
