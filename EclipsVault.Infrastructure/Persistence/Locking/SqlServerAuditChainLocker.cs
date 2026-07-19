using Microsoft.EntityFrameworkCore;

namespace EclipsVault.Infrastructure.Persistence.Locking;

/// <summary>
/// The chain lock on SQL Server.
/// </summary>
public sealed class SqlServerAuditChainLocker : IAuditChainLocker
{
    /// <summary>
    /// <c>@LockOwner = 'Transaction'</c> is the load-bearing word: the lock is released by the
    /// commit, which is exactly the window the head must be held for. sp_getapplock reports timeout
    /// and deadlock as a negative return rather than an error, so raise it — silently proceeding
    /// would append a row computed from a head someone else has already moved.
    /// </summary>
    private const string AcquireSql = """
        DECLARE @result int;
        EXEC @result = sp_getapplock
            @Resource = @p0, @LockMode = 'Exclusive', @LockOwner = 'Transaction', @LockTimeout = @p1;
        IF @result < 0
            THROW 51000, 'Could not acquire the audit chain lock; refusing to write an unchained audit row.', 1;
        """;

    public Task AcquireAsync(DbContext db, string resource, TimeSpan timeout, CancellationToken ct)
        => db.Database.ExecuteSqlRawAsync(AcquireSql, [resource, (int)timeout.TotalMilliseconds], ct);
}
