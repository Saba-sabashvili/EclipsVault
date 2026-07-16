using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace EclipsVault.Infrastructure.Persistence;

/// <summary>
/// Keeper of the audit hash-chain head. Every audit row is stamped through here (from the
/// SaveChanges interceptor, the single choke point for audit inserts) so sequence numbers and
/// hashes are assigned in one linear order.
///
/// <para>A hash chain is a linked list — row N commits to row N-1's hash — so appends cannot be
/// parallelised: two writers that both read head N would both mint N+1 and fork the chain. The head
/// must therefore be read and advanced under a lock held until the insert commits. That is inherent
/// to the tamper-evidence guarantee, not an implementation detail worth optimising away.</para>
///
/// <para>The lock and the head both live in the database, because an in-memory head is correct on
/// one node and silently wrong on two: each replica would seed its own head at startup and never
/// learn of the other's writes, so every audited write on the node that lost a race would collide
/// with the unique sequence index and roll back — permanently, since a losing node never advances.
/// Reading the head inside the lock, from the one place that actually knows it, is what makes
/// running more than one replica safe.</para>
/// </summary>
public sealed class AuditChain
{
    private const string LockResource = "EclipsVault:AuditChain";

    /// <summary>
    /// How long a writer waits for the chain before giving up. Generous, because contention here is
    /// normal and brief (one insert), and failing is expensive: the caller's whole operation aborts.
    /// </summary>
    private const int LockTimeoutMilliseconds = 15_000;

    /// <summary>
    /// A transaction-scoped exclusive lock, released automatically when the transaction ends —
    /// which is exactly the window the chain head must be held for. sp_getapplock reports timeout
    /// and deadlock as a negative return rather than an error, so raise it: silently proceeding
    /// would append a row computed from a head someone else has already moved.
    /// </summary>
    private const string AcquireLockSql = """
        DECLARE @result int;
        EXEC @result = sp_getapplock
            @Resource = @p0, @LockMode = 'Exclusive', @LockOwner = 'Transaction', @LockTimeout = @p1;
        IF @result < 0
            THROW 51000, 'Could not acquire the audit chain lock; refusing to write an unchained audit row.', 1;
        """;

    /// <summary>
    /// Takes the chain, reads its head, and stamps <paramref name="rows"/> onto it. The returned
    /// batch must be handed to <see cref="CommitAsync"/> or <see cref="AbortAsync"/> — until then
    /// the chain is held and every other writer, on any replica, waits.
    /// </summary>
    public async Task<AuditBatch> BeginAsync(DbContext db, IReadOnlyList<AuditLog> rows, CancellationToken ct)
    {
        // Join an ambient transaction when the caller opened one — their commit then ends our lock
        // at the right moment. Otherwise own one spanning lock -> read head -> stamp -> insert.
        var owned = db.Database.CurrentTransaction is null
            ? await db.Database.BeginTransactionAsync(ct)
            : null;

        try
        {
            await db.Database.ExecuteSqlRawAsync(AcquireLockSql, [LockResource, LockTimeoutMilliseconds], ct);

            var tail = await db.Set<AuditLog>()
                .AsNoTracking()
                .Where(a => a.Sequence > 0)
                .OrderByDescending(a => a.Sequence)
                .Select(a => new { a.Sequence, a.EntryHash })
                .FirstOrDefaultAsync(ct);

            Stamp(rows, tail?.Sequence ?? 0, tail?.EntryHash ?? AuditRowHasher.GenesisHash);
            return new AuditBatch(owned);
        }
        catch
        {
            if (owned is not null)
            {
                await owned.DisposeAsync();
            }

            throw;
        }
    }

    /// <summary>Commits the batch, which releases the chain. The head advances only now.</summary>
    public static async Task CommitAsync(AuditBatch batch, CancellationToken ct)
    {
        if (batch.OwnedTransaction is { } transaction)
        {
            await transaction.CommitAsync(ct);
            await transaction.DisposeAsync();
        }
    }

    /// <summary>
    /// Rolls the batch back, releasing the chain without advancing it — so a failed write leaves no
    /// gap and the next writer reuses the sequence numbers this one had claimed.
    /// </summary>
    public static async Task AbortAsync(AuditBatch batch)
    {
        if (batch.OwnedTransaction is { } transaction)
        {
            // Disposing an uncommitted transaction rolls it back.
            await transaction.DisposeAsync();
        }
    }

    private static void Stamp(IReadOnlyList<AuditLog> rows, long headSequence, string headHash)
    {
        var sequence = headSequence;
        var previous = headHash;

        foreach (var row in rows)
        {
            sequence++;
            row.Sequence = sequence;
            row.PreviousHash = previous;
            row.EntryHash = AuditRowHasher.Compute(row, previous);
            previous = row.EntryHash;
        }
    }
}

/// <summary>
/// One in-flight stamped batch. Holds the transaction the chain is locked by, when this writer
/// opened it; null means the caller owns the transaction and will end it themselves.
/// </summary>
public readonly record struct AuditBatch(IDbContextTransaction? OwnedTransaction);
