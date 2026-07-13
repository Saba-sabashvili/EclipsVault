using EclipsVault.Core.Domain.Entities;

namespace EclipsVault.Infrastructure.Persistence;

/// <summary>
/// Keeper of the audit hash-chain head. Every audit row is stamped through here (from the
/// SaveChanges interceptor, the single choke point for audit inserts) so sequence numbers and
/// hashes are assigned in one linear order. The head is seeded once from the persisted tail at
/// startup and advanced <b>only</b> when a batch commits — a rolled-back SaveChanges leaves the
/// head untouched, so no gap is ever created. The lock is held from <see cref="BeginAsync"/>
/// until <see cref="Commit"/>/<see cref="Abort"/>, serializing audited writes.
/// </summary>
public sealed class AuditChain
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private long _sequence;
    private string _hash = AuditRowHasher.GenesisHash;

    /// <summary>Sets the head from the persisted tail. Called once at startup, before any request.</summary>
    public void Seed(long lastSequence, string? lastHash)
    {
        _sequence = lastSequence;
        _hash = string.IsNullOrEmpty(lastHash) ? AuditRowHasher.GenesisHash : lastHash;
    }

    public async Task<AuditBatch> BeginAsync(IReadOnlyList<AuditLog> rows, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        return Stamp(rows);
    }

    public AuditBatch Begin(IReadOnlyList<AuditLog> rows)
    {
        _gate.Wait();
        return Stamp(rows);
    }

    private AuditBatch Stamp(IReadOnlyList<AuditLog> rows)
    {
        try
        {
            var seq = _sequence;
            var prev = _hash;
            foreach (var row in rows)
            {
                seq++;
                row.Sequence = seq;
                row.PreviousHash = prev;
                row.EntryHash = AuditRowHasher.Compute(row, prev);
                prev = row.EntryHash;
            }

            return new AuditBatch(seq, prev);
        }
        catch
        {
            _gate.Release();
            throw;
        }
    }

    /// <summary>Advances the head to the batch's end and releases the lock (after a successful commit).</summary>
    public void Commit(AuditBatch batch)
    {
        _sequence = batch.Sequence;
        _hash = batch.Hash;
        _gate.Release();
    }

    /// <summary>Releases the lock without advancing the head (after a failed/rolled-back commit).</summary>
    public void Abort() => _gate.Release();
}

/// <summary>The head reached after stamping a batch of rows; handed back to Commit on success.</summary>
public readonly record struct AuditBatch(long Sequence, string Hash);
