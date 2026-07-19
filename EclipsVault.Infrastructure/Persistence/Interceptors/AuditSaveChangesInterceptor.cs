using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Persistence.Interceptors;

/// <summary>
/// Injects an AuditLog row for every Secret insert/update/delete into the SAME
/// SaveChanges batch, which SQL Server executes as one implicit transaction.
/// Fail-closed by construction: if the audit row cannot be written the entire
/// transaction — including the secret change itself — is rolled back, and the
/// failure is surfaced as a critical event.
///
/// It is also the single choke point for <b>every</b> audit insert (whether injected here or
/// added by the <c>AuditSink</c>), so it stamps each new row into the tamper-evidence hash
/// chain just before persistence — advancing the chain head only once the batch commits.
/// </summary>
public sealed class AuditSaveChangesInterceptor : SaveChangesInterceptor
{
    private readonly IAuditContext _actor;
    private readonly AuditChain _chain;
    private readonly TimeProvider _clock;
    private readonly ILogger<AuditSaveChangesInterceptor> _logger;

    // The chain batch stamped for the in-flight SaveChanges (the chain lock is held while set).
    private AuditBatch? _pending;

    public AuditSaveChangesInterceptor(IAuditContext actor, AuditChain chain, TimeProvider clock, ILogger<AuditSaveChangesInterceptor> logger)
    {
        _actor = actor;
        _chain = chain;
        _clock = clock;
        _logger = logger;
    }

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        InjectAuditEntries(eventData.Context);
        var rows = CollectAddedAuditRows(eventData.Context);
        if (rows.Count > 0)
        {
            _pending = _chain.Begin(rows);
        }
        return base.SavingChanges(eventData, result);
    }

    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        InjectAuditEntries(eventData.Context);
        var rows = CollectAddedAuditRows(eventData.Context);
        if (rows.Count > 0)
        {
            _pending = await _chain.BeginAsync(rows, cancellationToken);
        }
        return await base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    public override int SavedChanges(SaveChangesCompletedEventData eventData, int result)
    {
        CommitChain();
        return base.SavedChanges(eventData, result);
    }

    public override ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
    {
        CommitChain();
        return base.SavedChangesAsync(eventData, result, cancellationToken);
    }

    public override void SaveChangesFailed(DbContextErrorEventData eventData)
    {
        LogFailure(eventData);
        AbortChain();
        base.SaveChangesFailed(eventData);
    }

    public override Task SaveChangesFailedAsync(DbContextErrorEventData eventData, CancellationToken cancellationToken = default)
    {
        LogFailure(eventData);
        AbortChain();
        return base.SaveChangesFailedAsync(eventData, cancellationToken);
    }

    private void CommitChain()
    {
        if (_pending is { } batch)
        {
            _chain.Commit(batch);
            _pending = null;
        }
    }

    private void AbortChain()
    {
        if (_pending is not null)
        {
            _chain.Abort();
            _pending = null;
        }
    }

    private static List<AuditLog> CollectAddedAuditRows(DbContext? context)
        => context?.ChangeTracker.Entries<AuditLog>()
            .Where(e => e.State == EntityState.Added)
            .Select(e => e.Entity)
            .ToList() ?? [];

    private void LogFailure(DbContextErrorEventData eventData)
        => _logger.LogCritical(eventData.Exception,
            "SaveChanges failed with pending audit entries — transaction aborted, no unaudited change was persisted (fail-closed)");

    private void InjectAuditEntries(DbContext? context)
    {
        if (context is null)
        {
            return;
        }

        var secretEntries = context.ChangeTracker.Entries<Secret>()
            .Where(e => e.State is EntityState.Added or EntityState.Modified or EntityState.Deleted)
            .ToList();

        if (secretEntries.Count == 0)
        {
            return;
        }

        var now = _clock.GetUtcNow();
        foreach (var entry in secretEntries)
        {
            var action = entry.State switch
            {
                EntityState.Added => AuditAction.SecretCreated,
                EntityState.Deleted => AuditAction.SecretDeleted,
                _ when IsShredTransition(entry) => AuditAction.SecretShredded,
                _ => AuditAction.SecretUpdated
            };

            context.Set<AuditLog>().Add(new AuditLog
            {
                Id = Guid.NewGuid(),
                TimestampUtc = now,
                UserId = _actor.UserId,
                Username = _actor.Username ?? "system",
                SourceIp = _actor.SourceIp ?? "internal",
                Action = action,
                ResourceType = nameof(Secret),
                ResourceId = entry.Entity.Id,
                ResourceName = entry.Entity.Name,
                Details = $"EntityState={entry.State}"
            });
        }
    }

    private static bool IsShredTransition(EntityEntry<Secret> entry)
        => entry.Property(s => s.IsShredded) is { OriginalValue: false, CurrentValue: true };
}
