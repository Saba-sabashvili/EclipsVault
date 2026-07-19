using Microsoft.EntityFrameworkCore;

namespace EclipsVault.Infrastructure.Persistence.Locking;

/// <summary>
/// Takes the cluster-wide lock that serialises appends to the audit hash chain.
///
/// The chain is a linked list — row N commits to row N-1's hash — so two writers that both read
/// head N would both mint N+1 and fork it. The head must be read and advanced under a lock held
/// until the insert commits. This is the only part of the chain that is database-specific, which is
/// why it is a port: SQL Server says <c>sp_getapplock</c> and PostgreSQL says
/// <c>pg_advisory_xact_lock</c>, but they mean the same thing.
///
/// <para><b>The lock must be transaction-scoped.</b> That is the whole contract, not an
/// implementation preference: it has to be held for exactly the window between reading the head and
/// committing the insert, and released by the commit itself. An implementation that cannot bind the
/// lock's lifetime to the transaction cannot satisfy this — which rules out a lease-based
/// distributed lock (Redis/Redlock and friends), where a writer whose lease quietly expires
/// mid-transaction still goes on to commit, mints a duplicate sequence, and takes the node down
/// with the unique index. The lock and the head must be held by the one thing that knows whether
/// the insert landed: the database.</para>
/// </summary>
public interface IAuditChainLocker
{
    /// <summary>
    /// Blocks until the chain is held by <paramref name="db"/>'s current transaction, or throws if
    /// it cannot be — never returns without the lock, since proceeding would append a row computed
    /// from a head someone else has already moved.
    /// </summary>
    Task AcquireAsync(DbContext db, string resource, TimeSpan timeout, CancellationToken ct);
}
