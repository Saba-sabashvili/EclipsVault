using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace EclipsVault.Infrastructure.Persistence.Repositories;

public sealed class SecretRepository : ISecretRepository
{
    private readonly EclipsVaultDbContext _context;

    public SecretRepository(EclipsVaultDbContext context) => _context = context;

    public Task<Secret?> FindAsync(Guid id, CancellationToken ct)
        => _context.Secrets.FirstOrDefaultAsync(s => s.Id == id, ct);

    public async Task<IReadOnlyList<Secret>> ListActiveAsync(DateTimeOffset asOfUtc, CancellationToken ct)
        => await _context.Secrets
            .AsNoTracking()
            .Where(s => !s.IsShredded && (s.ExpiresAtUtc == null || s.ExpiresAtUtc > asOfUtc))
            .OrderBy(s => s.Name)
            .ToListAsync(ct);

    public async Task<IReadOnlyList<Secret>> ListExpiredAsync(DateTimeOffset asOfUtc, CancellationToken ct)
        => await _context.Secrets
            .Where(s => !s.IsShredded && s.ExpiresAtUtc != null && s.ExpiresAtUtc <= asOfUtc)
            .ToListAsync(ct);

    public async Task<IReadOnlyList<Secret>> ListExpiringAsync(DateTimeOffset asOfUtc, DateTimeOffset horizonUtc, CancellationToken ct)
        => await _context.Secrets
            .Where(s => !s.IsShredded
                        && s.ExpiresAtUtc != null
                        && s.ExpiresAtUtc > asOfUtc
                        && s.ExpiresAtUtc <= horizonUtc
                        && (s.ExpiryNoticeSentForUtc == null || s.ExpiryNoticeSentForUtc != s.ExpiresAtUtc))
            .OrderBy(s => s.ExpiresAtUtc)
            .ToListAsync(ct);

    public async Task AddAsync(Secret secret, CancellationToken ct)
    {
        _context.Secrets.Add(secret);
        await SaveOrDiscardAsync(ct, secret); // audit row injected atomically by the interceptor
    }

    public async Task UpdateAsync(Secret secret, CancellationToken ct)
    {
        _context.Secrets.Update(secret);
        await SaveOrDiscardAsync(ct, secret);
    }

    public async Task MarkExpiryNoticeSentAsync(Secret secret, CancellationToken ct)
    {
        // Mark the single column rather than the whole entity: DbSet.Update() flags every property
        // as modified, which the audit interceptor cannot tell apart from a genuine edit.
        _context.Entry(secret).Property(s => s.ExpiryNoticeSentForUtc).IsModified = true;
        await SaveOrDiscardAsync(ct, secret);
    }

    public async Task DeleteAsync(Secret secret, CancellationToken ct)
    {
        _context.Secrets.Remove(secret); // archived versions cascade-delete via the FK
        await SaveOrDiscardAsync(ct, secret);
    }

    public async Task RotateAsync(Secret secret, SecretVersion archivedVersion, CancellationToken ct)
    {
        _context.SecretVersions.Add(archivedVersion);
        _context.Secrets.Update(secret);
        await SaveOrDiscardAsync(ct, secret, archivedVersion); // interceptor injects the SecretUpdated audit atomically
    }

    public async Task ShredAsync(Secret secret, CancellationToken ct)
    {
        // Archived versions hold key material — purge them as part of the shred.
        var versions = await _context.SecretVersions.Where(v => v.SecretId == secret.Id).ToListAsync(ct);
        _context.SecretVersions.RemoveRange(versions);
        _context.Secrets.Update(secret);
        await SaveOrDiscardAsync(ct, [secret, .. versions]); // interceptor injects the SecretShredded audit
    }

    /// <summary>
    /// Saves, or leaves the entities exactly as it found them.
    ///
    /// EF keeps a failed SaveChanges pending so it can be retried, but this context is scoped to the
    /// request and shared — the audit sink saves on it too, and SaveChanges flushes everything
    /// pending, not just the row its caller added. So a write that failed would be committed by the
    /// next unrelated audit write, storing a value the caller was told had not been stored. For a
    /// managed secret that is the drift this vault exists to prevent, and it lands in the same
    /// commit as the audit row reporting the failure, leaving the trail contradicting itself.
    ///
    /// A write that reports failure must leave nothing behind for someone else to commit.
    /// </summary>
    private async Task SaveOrDiscardAsync(CancellationToken ct, params object[] touched)
    {
        try
        {
            await _context.SaveChangesAsync(ct);
        }
        catch
        {
            foreach (var entry in touched.Select(_context.Entry))
            {
                if (entry.State == EntityState.Added)
                {
                    entry.State = EntityState.Detached;
                }
                else
                {
                    // Rewinds the entity itself, not just the tracker: the caller still holds this
                    // instance and must not see a change that did not happen.
                    entry.CurrentValues.SetValues(entry.OriginalValues);
                    entry.State = EntityState.Unchanged;
                }
            }

            throw;
        }
    }

    public async Task<IReadOnlyList<SecretVersion>> ListVersionsAsync(Guid secretId, CancellationToken ct)
        => await _context.SecretVersions
            .AsNoTracking()
            .Where(v => v.SecretId == secretId)
            .OrderByDescending(v => v.VersionNumber)
            .ToListAsync(ct);

    public Task<SecretVersion?> FindVersionAsync(Guid secretId, Guid versionId, CancellationToken ct)
        => _context.SecretVersions.FirstOrDefaultAsync(v => v.Id == versionId && v.SecretId == secretId, ct);

    public Task<int> CountVersionsAsync(Guid secretId, CancellationToken ct)
        => _context.SecretVersions.CountAsync(v => v.SecretId == secretId, ct);
}
