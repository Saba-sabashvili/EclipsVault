namespace EclipsVault.Core.Application.Authentication;

/// <summary>The outcome of the password stage, distinguishing rejection from the two-factor paths that follow.</summary>
public enum CredentialStatus
{
    Invalid = 0,
    RequiresTotp = 1,
    RequiresTotpEnrollment = 2
}
