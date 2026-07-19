using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Exceptions;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Persistence;

/// <summary>
/// The one place audit rows are written. Appends the entry and commits it on its own
/// SaveChanges; any failure is escalated to a critical log and rethrown as
/// <see cref="AuditWriteFailedException"/> so the caller aborts (fail-closed).
/// </summary>
public sealed class AuditSink : IAuditSink
{
    private readonly EclipsVaultDbContext _db;
    private readonly IAuditContext _actor;
    private readonly TimeProvider _clock;
    private readonly ILogger<AuditSink> _logger;

    public AuditSink(EclipsVaultDbContext db, IAuditContext actor, TimeProvider clock, ILogger<AuditSink> logger)
    {
        _db = db;
        _actor = actor;
        _clock = clock;
        _logger = logger;
    }

    public async Task WriteAsync(AuditEntry entry, CancellationToken ct)
    {
        try
        {
            _db.AuditLogs.Add(new AuditLog
            {
                Id = Guid.NewGuid(),
                TimestampUtc = _clock.GetUtcNow(),
                UserId = entry.ActorUserId ?? _actor.UserId,
                Username = entry.ActorUsername ?? _actor.Username ?? "system",
                SourceIp = _actor.SourceIp ?? "internal",
                Action = entry.Action,
                ResourceType = entry.ResourceType,
                ResourceId = entry.ResourceId,
                ResourceName = entry.ResourceName,
                Details = entry.Details,
                IsCritical = entry.IsCritical
            });
            await _db.SaveChangesAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogCritical(ex,
                "Audit write failed for {AuditAction} on {ResourceType} {ResourceId} — operation aborted (fail-closed)",
                entry.Action, entry.ResourceType, entry.ResourceId);
            throw new AuditWriteFailedException(
                $"The audit trail could not be persisted for '{entry.Action}' on {entry.ResourceType} '{entry.ResourceId}'. " +
                "The operation was aborted before any secret material was released (fail-closed).", ex);
        }
    }
}
