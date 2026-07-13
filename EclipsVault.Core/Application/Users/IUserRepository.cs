using EclipsVault.Core.Domain.Entities;

namespace EclipsVault.Core.Application.Users;

public interface IUserRepository
{
    Task<User?> FindByUsernameAsync(string username, CancellationToken ct);

    /// <summary>Looks up an account by either its login username or its email address.</summary>
    Task<User?> FindByUsernameOrEmailAsync(string identifier, CancellationToken ct);

    /// <summary>Returns existing emails whose local part is <c>localPrefix.*</c> at the given domain — used to pick the next unique sequence.</summary>
    Task<IReadOnlyList<string>> FindEmailsWithPrefixAsync(string localPrefix, string domain, CancellationToken ct);

    Task<User?> FindByIdAsync(Guid id, CancellationToken ct);

    Task<IReadOnlyList<User>> ListAsync(CancellationToken ct);

    Task AddAsync(User user, CancellationToken ct);

    Task UpdateAsync(User user, CancellationToken ct);

    Task DeleteAsync(User user, CancellationToken ct);

    Task<byte[]?> GetAvatarPngAsync(Guid userId, CancellationToken ct);

    /// <summary>Upserts the avatar blob and stamps <see cref="User.AvatarUpdatedAtUtc"/> in one transaction.</summary>
    Task SetAvatarAsync(User user, byte[] png, CancellationToken ct);

    /// <summary>Deletes the avatar blob and clears <see cref="User.AvatarUpdatedAtUtc"/> in one transaction.</summary>
    Task RemoveAvatarAsync(User user, CancellationToken ct);

}
