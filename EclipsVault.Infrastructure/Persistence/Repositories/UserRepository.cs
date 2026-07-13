using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace EclipsVault.Infrastructure.Persistence.Repositories;

public sealed class UserRepository : IUserRepository
{
    private readonly EclipsVaultDbContext _context;
    private readonly TimeProvider _clock;

    public UserRepository(EclipsVaultDbContext context, TimeProvider clock)
    {
        _context = context;
        _clock = clock;
    }

    public Task<User?> FindByUsernameAsync(string username, CancellationToken ct)
        => _context.Users.FirstOrDefaultAsync(u => u.Username == username, ct);

    public Task<User?> FindByUsernameOrEmailAsync(string identifier, CancellationToken ct)
        => _context.Users.FirstOrDefaultAsync(u => u.Username == identifier || u.Email == identifier, ct);

    public async Task<IReadOnlyList<string>> FindEmailsWithPrefixAsync(string localPrefix, string domain, CancellationToken ct)
    {
        var pattern = $"{localPrefix}.%@{domain}";
        return await _context.Users
            .AsNoTracking()
            .Where(u => EF.Functions.Like(u.Email, pattern))
            .Select(u => u.Email)
            .ToListAsync(ct);
    }

    public Task<User?> FindByIdAsync(Guid id, CancellationToken ct)
        => _context.Users.FirstOrDefaultAsync(u => u.Id == id, ct);

    public async Task<IReadOnlyList<User>> ListAsync(CancellationToken ct)
        => await _context.Users.AsNoTracking().OrderBy(u => u.Username).ToListAsync(ct);

    public async Task AddAsync(User user, CancellationToken ct)
    {
        _context.Users.Add(user);
        await _context.SaveChangesAsync(ct);
    }

    public async Task UpdateAsync(User user, CancellationToken ct)
    {
        _context.Users.Update(user);
        await _context.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(User user, CancellationToken ct)
    {
        _context.Users.Remove(user);
        await _context.SaveChangesAsync(ct);
    }

    public Task<byte[]?> GetAvatarPngAsync(Guid userId, CancellationToken ct)
        => _context.UserAvatars
            .AsNoTracking()
            .Where(a => a.UserId == userId)
            .Select(a => a.Png)
            .FirstOrDefaultAsync(ct)!;

    public async Task SetAvatarAsync(User user, byte[] png, CancellationToken ct)
    {
        var now = _clock.GetUtcNow();
        var existing = await _context.UserAvatars.FirstOrDefaultAsync(a => a.UserId == user.Id, ct);
        if (existing is null)
        {
            _context.UserAvatars.Add(new UserAvatar { UserId = user.Id, Png = png, UpdatedAtUtc = now });
        }
        else
        {
            existing.Png = png;
            existing.UpdatedAtUtc = now;
        }

        user.AvatarUpdatedAtUtc = now;
        _context.Users.Update(user);
        await _context.SaveChangesAsync(ct);
    }

    public async Task RemoveAvatarAsync(User user, CancellationToken ct)
    {
        var existing = await _context.UserAvatars.FirstOrDefaultAsync(a => a.UserId == user.Id, ct);
        if (existing is not null)
        {
            _context.UserAvatars.Remove(existing);
        }

        user.AvatarUpdatedAtUtc = null;
        _context.Users.Update(user);
        await _context.SaveChangesAsync(ct);
    }

}
