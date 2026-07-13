using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Profile;

public sealed record ProfileDto(
    Guid Id,
    string Username,
    string DisplayName,
    string Email,
    ClearanceLevel Clearance,
    string ProjectKey,
    bool TotpEnabled,
    bool HasCustomAvatar);

/// <summary>
/// Self-service account management for the signed-in user: display name and email,
/// profile picture, password, and their own MFA enrollment. Every mutation is
/// audited. Nothing here can change a user's clearance or project — that is an
/// administrative action (see <see cref="IUserAdminService"/>).
/// </summary>
public interface IProfileService
{
    Task<ProfileDto?> GetAsync(Guid userId, CancellationToken ct);

    /// <summary>Updates display name and email. Returns the refreshed profile. Throws ProfileException on invalid input.</summary>
    Task<ProfileDto> UpdateAsync(Guid userId, string displayName, string email, CancellationToken ct);

    /// <summary>Verifies the current password before setting a new one. Throws ProfileException on mismatch or a weak password.</summary>
    Task ChangePasswordAsync(Guid userId, string currentPassword, string newPassword, CancellationToken ct);

    Task<byte[]?> GetAvatarPngAsync(Guid userId, CancellationToken ct);

    /// <summary>Validates and re-encodes the uploaded image to a safe PNG, then stores it. Throws ProfileException if unreadable.</summary>
    Task SetAvatarAsync(Guid userId, byte[] uploadedBytes, CancellationToken ct);

    Task RemoveAvatarAsync(Guid userId, CancellationToken ct);

    /// <summary>Clears the user's TOTP so they re-enroll a fresh authenticator at next sign-in.</summary>
    Task ResetOwnMfaAsync(Guid userId, CancellationToken ct);
}
