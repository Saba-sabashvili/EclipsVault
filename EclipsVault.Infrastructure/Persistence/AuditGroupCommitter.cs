using System.Threading.Channels;
using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Exceptions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Persistence;

/// <summary>
/// Group commit for the audit chain — the engine behind <see cref="AuditSink"/>.
///
/// The chain is a linked list, so appends serialize on one cluster-wide lock held across
/// read-head → insert → commit. Every secret reveal is audited fail-closed before decryption, so
/// that lock sat on the read path: one lock cycle per reveal. Measured, it peaked near 400 reveals
/// per second at a concurrency of 2–4 and then went <i>backwards</i> — about 120/sec at 32 callers,
/// half the single-threaded rate, with a 2.5-second p99, while the same rows written without the
/// chain scaled past 4,000/sec. The database was never the limit; the convoy at the lock was.
///
/// But the chain never needed a lock per row. <see cref="AuditChain.BeginAsync"/> stamps a whole
/// list, so the lock's cost is per <i>batch</i>. This collects the rows waiting at any moment and
/// commits them as one — the same trick a database uses for its own write-ahead log.
///
/// <b>Fail-closed is untouched, and that is the point.</b> Every caller still waits for its own row
/// to be committed before it is allowed to continue; a batch that fails aborts every operation in
/// it. This is the opposite of an asynchronous audit outbox, where callers proceed and rows can be
/// lost in a crash — leaving a change committed with nothing recording it. Here nobody proceeds
/// early. They just wait together instead of in a queue.
///
/// The batch window is not a timer. A batch is whatever accumulated while the previous batch was
/// committing, so latency is never worse than a single write (under no load, batches are size 1)
/// and batches grow exactly when contention would otherwise have formed.
/// </summary>
public sealed class AuditGroupCommitter : BackgroundService
{
    /// <summary>
    /// Ceiling on rows per chained transaction. Large enough that the lock cost per row disappears,
    /// small enough that one failure cannot abort an unbounded number of unrelated operations.
    /// </summary>
    private const int MaxBatch = 256;

    private readonly record struct Pending(AuditLog Row, TaskCompletionSource Committed);

    private readonly Channel<Pending> _queue = Channel.CreateUnbounded<Pending>(
        new UnboundedChannelOptions { SingleReader = true });

    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<AuditGroupCommitter> _logger;

    public AuditGroupCommitter(IServiceScopeFactory scopes, ILogger<AuditGroupCommitter> logger)
    {
        _scopes = scopes;
        _logger = logger;
    }

    /// <summary>
    /// Queues <paramref name="row"/> and completes once it is durably committed and chained. Throws
    /// <see cref="AuditWriteFailedException"/> if it cannot be — the caller must then abort before
    /// releasing any secret material.
    /// </summary>
    public Task CommitAsync(AuditLog row, CancellationToken ct)
    {
        var committed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        if (!_queue.Writer.TryWrite(new Pending(row, committed)))
        {
            // Only when the writer has shut down. Refuse rather than drop the row on the floor.
            throw new AuditWriteFailedException(
                $"The audit writer is not accepting entries, so '{row.Action}' could not be recorded. " +
                "The operation was aborted before any secret material was released (fail-closed).");
        }

        return committed.Task.WaitAsync(ct);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (await _queue.Reader.WaitToReadAsync(stoppingToken))
            {
                var batch = DrainWaiting();
                if (batch.Count > 0)
                {
                    // Deliberately not the stopping token: a batch in flight is a set of callers
                    // holding their breath, and cancelling it mid-commit would leave them unsure
                    // whether their row landed. Let it finish; shutdown waits.
                    await FlushAsync(batch, CancellationToken.None);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Shutting down.
        }
        finally
        {
            FailRemaining();
        }
    }

    /// <summary>Everything queued right now, up to <see cref="MaxBatch"/> — the natural batch.</summary>
    private List<Pending> DrainWaiting()
    {
        var batch = new List<Pending>();
        while (batch.Count < MaxBatch && _queue.Reader.TryRead(out var pending))
        {
            batch.Add(pending);
        }

        return batch;
    }

    private async Task FlushAsync(List<Pending> batch, CancellationToken ct)
    {
        try
        {
            // Its own scope, and so its own connection: these rows are standalone by definition
            // (a reveal, a sign-in), never atomic with an entity change — that is the interceptor's
            // job — so they must not ride on, or flush, a request's unit of work.
            await using var scope = _scopes.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<EclipsVaultDbContext>();

            foreach (var pending in batch)
            {
                db.Set<AuditLog>().Add(pending.Row);
            }

            // One SaveChanges: the interceptor stamps every row into the chain under one lock.
            await db.SaveChangesAsync(ct);

            foreach (var pending in batch)
            {
                pending.Committed.TrySetResult();
            }
        }
        catch (Exception ex)
        {
            // One bad row aborts its whole batch. That is the safe direction — an operation refused
            // when it could have proceeded costs a retry; one allowed through unaudited costs the
            // guarantee. It cannot poison the queue: the batch is already out of it.
            _logger.LogCritical(ex,
                "An audit batch of {Count} row(s) could not be committed — every operation waiting on it is being aborted (fail-closed)",
                batch.Count);

            var failure = new AuditWriteFailedException(
                $"The audit trail could not be persisted for a batch of {batch.Count} entr(ies). " +
                "The operations waiting on it were aborted before any secret material was released (fail-closed).", ex);

            foreach (var pending in batch)
            {
                pending.Committed.TrySetException(failure);
            }
        }
    }

    /// <summary>
    /// Fails anyone still queued at shutdown. A caller left waiting on a promise nobody will keep is
    /// a request that never fails closed — it just hangs, which is the one outcome worse than an error.
    /// </summary>
    private void FailRemaining()
    {
        _queue.Writer.TryComplete();

        while (_queue.Reader.TryRead(out var pending))
        {
            pending.Committed.TrySetException(new AuditWriteFailedException(
                "The vault is shutting down and the audit trail could not be persisted. " +
                "The operation was aborted before any secret material was released (fail-closed)."));
        }
    }
}
