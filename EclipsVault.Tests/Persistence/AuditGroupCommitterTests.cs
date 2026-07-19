using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Core.Domain.Exceptions;
using EclipsVault.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace EclipsVault.Tests.Persistence;

/// <summary>
/// Group commit exists because the chain lock capped the read path: every reveal is audited
/// fail-closed before decryption, so one lock cycle per reveal put a cluster-wide bottleneck on
/// serving secrets. Batching removes it — but only if it changes nothing a caller can observe.
///
/// So these pin the property, not the speed: a caller is released only once its own row is
/// committed, and a batch that fails aborts every operation waiting on it. The alternative design
/// (an async outbox) would be far faster still and would quietly break exactly this.
///
/// Runs against in-memory SQLite without the audit interceptor, which needs SQL Server for the
/// chain lock; that the batched rows chain correctly is verified against the real database.
/// </summary>
public class AuditGroupCommitterTests : IAsyncLifetime
{
    private SqliteConnection _connection = null!;
    private ServiceProvider _provider = null!;
    private AuditGroupCommitter _committer = null!;
    private CountingInterceptor _saves = null!;

    /// <summary>
    /// Holds one SaveChanges open inside the interceptor until the test lets it go.
    ///
    /// These tests need the flush loop to be <em>provably</em> mid-save while more rows are queued
    /// behind it. Stalling it for 300ms and queueing 50ms later only assumed that, and on a loaded
    /// CI runner the assumption lost: the queueing outran the stall, the rows drained across many
    /// batches, and a test that asserts batching failed for reasons that had nothing to do with
    /// batching. Waiting on the save to actually begin, rather than on a clock, removes the race
    /// instead of making it rarer.
    /// </summary>
    private sealed class SaveGate
    {
        private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _released = new(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>Completes once the flush loop is inside SaveChanges and cannot drain anything else.</summary>
        public Task Entered => _entered.Task;

        public void Release() => _released.TrySetResult();

        internal Task Reached()
        {
            _entered.TrySetResult();
            return _released.Task;
        }
    }

    /// <summary>Counts SaveChanges calls, and can hold one open on request.</summary>
    private sealed class CountingInterceptor : SaveChangesInterceptor
    {
        private int _saves;
        private SaveGate? _gate;

        public int Saves => Volatile.Read(ref _saves);

        /// <summary>Arms a one-shot gate on whichever save begins next.</summary>
        public SaveGate HoldNextSave()
        {
            var gate = new SaveGate();
            Volatile.Write(ref _gate, gate);
            return gate;
        }

        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _saves);

            if (Interlocked.Exchange(ref _gate, null) is { } gate)
            {
                await gate.Reached();
            }

            return await base.SavingChangesAsync(eventData, result, cancellationToken);
        }
    }

    public async Task InitializeAsync()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        _saves = new CountingInterceptor();

        var services = new ServiceCollection();
        services.AddDbContext<EclipsVaultDbContext>(o => o.UseSqlite(_connection).AddInterceptors(_saves));
        _provider = services.BuildServiceProvider();

        await ReadAsync(db => db.Database.EnsureCreatedAsync());

        _committer = new AuditGroupCommitter(
            _provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<AuditGroupCommitter>.Instance);
        await _committer.StartAsync(CancellationToken.None);
    }

    public async Task DisposeAsync()
    {
        await _committer.StopAsync(CancellationToken.None);
        await _provider.DisposeAsync();
        _connection.Dispose();
    }

    private static AuditLog Row(Guid? id = null) => new()
    {
        Id = id ?? Guid.NewGuid(),
        TimestampUtc = DateTimeOffset.UtcNow,
        Username = "dev-user",
        SourceIp = "::1",
        Action = AuditAction.SecretRevealed,
        ResourceType = nameof(Secret),
        ResourceId = Guid.NewGuid(),
        ResourceName = "app_probe_password"
    };

    /// <summary>Each read gets its own scope — the committer's contexts are scoped too.</summary>
    private async Task<T> ReadAsync<T>(Func<EclipsVaultDbContext, Task<T>> read)
    {
        await using var scope = _provider.CreateAsyncScope();
        return await read(scope.ServiceProvider.GetRequiredService<EclipsVaultDbContext>());
    }

    private Task<int> CountAsync() => ReadAsync(db => db.AuditLogs.CountAsync());

    [Fact]
    public async Task A_caller_is_released_only_once_its_row_is_committed()
    {
        // The whole fail-closed premise: a reveal is audited BEFORE decryption, so this returning
        // is what makes the row's existence a precondition of the plaintext.
        var row = Row();

        await _committer.CommitAsync(row, CancellationToken.None);

        Assert.True(await ReadAsync(db => db.AuditLogs.AsNoTracking().AnyAsync(a => a.Id == row.Id)));
    }

    [Fact]
    public async Task A_row_that_cannot_be_committed_aborts_its_caller()
    {
        var existing = Row();
        await _committer.CommitAsync(existing, CancellationToken.None);

        // Same primary key: the insert cannot succeed.
        await Assert.ThrowsAsync<AuditWriteFailedException>(
            () => _committer.CommitAsync(Row(existing.Id), CancellationToken.None));
    }

    [Fact]
    public async Task A_batch_that_fails_aborts_every_caller_in_it()
    {
        // One bad row takes its whole batch down. That is the safe direction: an operation refused
        // when it could have proceeded costs a retry; one let through unaudited costs the guarantee.
        var poison = Row();
        await _committer.CommitAsync(poison, CancellationToken.None);

        var gate = _saves.HoldNextSave();
        var blocker = _committer.CommitAsync(Row(), CancellationToken.None);
        await gate.Entered;

        // CommitAsync queues synchronously, so all three are waiting before the gate opens and are
        // drained into one batch — with the duplicate.
        var batched = new[] { Row(), Row(poison.Id), Row() }
            .Select(r => _committer.CommitAsync(r, CancellationToken.None))
            .ToArray();

        gate.Release();
        await blocker;
        var failures = await Task.WhenAll(batched.Select(async t =>
        {
            try
            {
                await t;
                return null;
            }
            catch (AuditWriteFailedException ex)
            {
                return (Exception?)ex;
            }
        }));

        Assert.All(failures, f => Assert.IsType<AuditWriteFailedException>(f));
    }

    [Fact]
    public async Task Concurrent_callers_all_get_their_row_written_exactly_once()
    {
        var rows = Enumerable.Range(0, 200).Select(_ => Row()).ToArray();

        await Task.WhenAll(rows.Select(r => _committer.CommitAsync(r, CancellationToken.None)));

        Assert.Equal(rows.Length, await CountAsync());

        var stored = await ReadAsync(db => db.AuditLogs.AsNoTracking().Select(a => a.Id).ToListAsync());
        Assert.Equal(rows.Select(r => r.Id).OrderBy(x => x), stored.OrderBy(x => x));
    }

    [Fact]
    public async Task Rows_waiting_together_are_committed_together()
    {
        // The point of the exercise: the chain lock is taken once per SaveChanges, so batching is
        // what turns one lock per reveal into one lock per group.
        var gate = _saves.HoldNextSave();

        var blocker = _committer.CommitAsync(Row(), CancellationToken.None);
        await gate.Entered; // the loop is inside SaveChanges and can drain nothing until released

        // CommitAsync writes to the channel synchronously, so once this returns all 100 are queued.
        var queued = Enumerable.Range(0, 100)
            .Select(_ => _committer.CommitAsync(Row(), CancellationToken.None))
            .ToArray();

        gate.Release();
        await blocker;
        await Task.WhenAll(queued);

        Assert.Equal(101, await CountAsync());

        // 101 rows, two lock cycles: the held save, then every row that accumulated behind it in a
        // single batch. Exactly two, not "somewhere under ten" — the batch is whatever was waiting,
        // so with all 100 provably waiting there is nothing left to need a third.
        Assert.Equal(2, _saves.Saves);
    }

    [Fact]
    public async Task Shutting_down_refuses_new_entries_rather_than_hanging_their_callers()
    {
        // A caller left waiting on a promise nobody will keep never fails closed — it just hangs,
        // which is the one outcome worse than an error.
        await _committer.StopAsync(CancellationToken.None);

        await Assert.ThrowsAsync<AuditWriteFailedException>(
            () => _committer.CommitAsync(Row(), CancellationToken.None));
    }
}
