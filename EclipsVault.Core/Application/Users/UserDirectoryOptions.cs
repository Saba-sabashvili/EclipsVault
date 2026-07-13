namespace EclipsVault.Core.Application.Users;

/// <summary>
/// Directory settings for user provisioning. The email domain is combined with a
/// generated <c>first.last.N</c> local part to produce each account's unique email.
/// </summary>
public sealed record UserDirectoryOptions(string EmailDomain)
{
    public static readonly UserDirectoryOptions Default = new("eclipsvault.local");
}
