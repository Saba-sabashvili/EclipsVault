using EclipsVault.Core.Application.Secrets;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Re-wraps every non-shredded secret's (and archived version's) DEK under the current KEK. Only the
/// wrapped-DEK and KekId change — the AES-GCM payload ciphertext is untouched, so rotation is cheap and
/// never decrypts a secret's plaintext (honey-tokens included). Each re-wrapped secret is audited by the
/// SaveChanges interceptor, and a critical <c>KekRotated</c> summary row records the pass.
/// </summary>
public sealed class KekRotationService : IKekRotationService
{
    private readonly EclipsVaultDbContext _db;
    private readonly ICryptoEngineFactory _cryptoFactory;
    private readonly IKekProvider _kek;
    private readonly IAuditSink _audit;

    public KekRotationService(EclipsVaultDbContext db, ICryptoEngineFactory cryptoFactory, IKekProvider kek, IAuditSink audit)
    {
        _db = db;
        _cryptoFactory = cryptoFactory;
        _kek = kek;
        _audit = audit;
    }

    public async Task<KekStatus> GetStatusAsync(CancellationToken ct)
    {
        var current = _kek.CurrentKekId;
        var known = _kek.KnownKekIds;

        var secretGroups = await _db.Secrets.AsNoTracking()
            .Where(s => !s.IsShredded)
            .GroupBy(s => s.KekId)
            .Select(g => new { KekId = g.Key, Count = g.Count() })
            .ToListAsync(ct);

        var versionGroups = await _db.SecretVersions.AsNoTracking()
            .GroupBy(v => v.KekId)
            .Select(g => new { KekId = g.Key, Count = g.Count() })
            .ToListAsync(ct);

        var kekIds = secretGroups.Select(g => g.KekId)
            .Concat(versionGroups.Select(g => g.KekId))
            .Concat(known)
            .Distinct(StringComparer.Ordinal);

        var usage = kekIds
            .Select(id => new KekUsage(
                id,
                IsCurrent: id == current,
                IsKnown: known.Contains(id),
                SecretCount: secretGroups.FirstOrDefault(g => g.KekId == id)?.Count ?? 0,
                VersionCount: versionGroups.FirstOrDefault(g => g.KekId == id)?.Count ?? 0))
            .OrderByDescending(u => u.IsCurrent)
            .ThenByDescending(u => u.Total)
            .ThenBy(u => u.KekId, StringComparer.Ordinal)
            .ToList();

        return new KekStatus(current, known, usage);
    }

    public async Task<KekRotationResult> RotateAsync(CancellationToken ct)
    {
        var engine = _cryptoFactory.Create();
        var current = _kek.CurrentKekId;

        var secrets = await _db.Secrets.Where(s => !s.IsShredded && s.KekId != current).ToListAsync(ct);
        foreach (var s in secrets)
        {
            var rewrapped = await engine.RewrapAsync(s.ToSealedSecret(), ct);
            s.ApplyEnvelope(rewrapped);
        }

        var versions = await _db.SecretVersions.Where(v => v.KekId != current).ToListAsync(ct);
        foreach (var v in versions)
        {
            var rewrapped = await engine.RewrapAsync(v.ToSealedSecret(), ct);
            v.ApplyEnvelope(rewrapped);
        }

        if (secrets.Count > 0 || versions.Count > 0)
        {
            await _db.SaveChangesAsync(ct);
        }

        await _audit.WriteAsync(new AuditEntry
        {
            Action = AuditAction.KekRotated,
            ResourceType = "Kek",
            ResourceName = current,
            Details = $"Re-wrapped {secrets.Count} secret(s) and {versions.Count} archived version(s) under KEK {current}",
            IsCritical = true
        }, ct);

        return new KekRotationResult(current, secrets.Count, versions.Count);
    }
}
