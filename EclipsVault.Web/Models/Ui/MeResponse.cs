namespace EclipsVault.Web.Models.Ui;

/// <summary>
/// The signed-in vault account, as the Angular UI sees it. Every field is chosen here, so nothing
/// added to the principal or to a Core type reaches the browser unless it is added to this record.
/// </summary>
/// <param name="Username">The immutable login username.</param>
/// <param name="DisplayName">The name to show, falling back to the username.</param>
/// <param name="Clearance">The clearance's display name, e.g. "Top Secret".</param>
/// <param name="Project">The project the account belongs to.</param>
/// <param name="Areas">Area keys authorized for this session by the pages' named policies.</param>
/// <param name="AvatarUrl">The account's avatar, from the existing avatar endpoint.</param>
/// <param name="LicenseNotice">The licensing reminder, only for a session that can act on it; otherwise null.</param>
public sealed record MeResponse(
    string Username,
    string DisplayName,
    string Clearance,
    string Project,
    IReadOnlyList<string> Areas,
    string AvatarUrl,
    LicenseNotice? LicenseNotice);
