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

    /// <summary>Counts SaveChanges calls, and can stall the first one so a batch has time to form.</summary>
    private sealed class CountingInterceptor : SaveChangesInterceptor
    {
        private int _saves;
        public int Saves => Volatile.Read(ref _saves);
        public TimeSpan FirstSaveDelay { get; set; } = TimeSpan.Zero;

        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _saves) == 1 && FirstSaveDelay > TimeSpan.Zero)
            {
                await Task.Delay(FirstSaveDelay, cancellationToken);
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

        _saves.FirstSaveDelay = TimeSpan.FromMilliseconds(300); // hold the loop so a batch forms

        var blocker = _committer.CommitAsync(Row(), CancellationToken.None);
        await Task.Delay(50);

        // These pile up behind the stalled save and are drained together — with the duplicate.
        var batched = new[] { Row(), Row(poison.Id), Row() }
            .Select(r => _committer.CommitAsync(r, CancellationToken.None))
            .ToArray();

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
        _saves.FirstSaveDelay = TimeSpan.FromMilliseconds(300);

        var blocker = _committer.CommitAsync(Row(), CancellationToken.None);
        await Task.Delay(50);

        var queued = Enumerable.Range(0, 100)
            .Select(_ => _committer.CommitAsync(Row(), CancellationToken.None))
            .ToArray();

        await blocker;
        await Task.WhenAll(queued);

        Assert.Equal(101, await CountAsync());
        // 101 rows, but nothing like 101 lock cycles: the stalled first save let the rest pile up.
        Assert.InRange(_saves.Saves, 2, 10);
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
