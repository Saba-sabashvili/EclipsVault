using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Domain.Entities;
using EclipsVault.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace EclipsVault.Infrastructure.Security.Licensing;

/// <summary>
/// Stores the evaluation window in the vault's own database. Singleton, like the recorder that uses
/// it, so it takes a scope of its own for each read or write. It deliberately does not swallow
/// failures: the caller decides what a storage failure means, and for the gate that decision is to
/// allow the operation.
/// </summary>
public sealed class EvaluationWindowStore : IEvaluationWindowStore
{
    private readonly IServiceScopeFactory _scopes;
    private readonly TimeProvider _time;

    public EvaluationWindowStore(IServiceScopeFactory scopes, TimeProvider time)
    {
        _scopes = scopes;
        _time = time;
    }

    public async Task<DateTimeOffset?> PeekAsync(string featureKey, CancellationToken ct)
    {
        await using var scope = _scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<EclipsVaultDbContext>();
        var row = await Find(db, featureKey, ct);
        return row?.StartedAtUtc;
    }

    public async Task<EvaluationStart> GetOrStartAsync(string featureKey, CancellationToken ct)
    {
        await using var scope = _scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<EclipsVaultDbContext>();

        var existing = await Find(db, featureKey, ct);
        if (existing is not null)
            return new EvaluationStart(existing.StartedAtUtc, StartedNow: false);

        var startedAt = _time.GetUtcNow();
        db.FeatureEvaluations.Add(new FeatureEvaluation { FeatureKey = featureKey, StartedAtUtc = startedAt });

        try
        {
            await db.SaveChangesAsync(ct);
            return new EvaluationStart(startedAt, StartedNow: true);
        }
        catch (DbUpdateException)
        {
            // Another replica opened the window between our read and our write. The feature key is
            // the primary key, so exactly one insert can win; adopt the winner's start rather than
            // handing this node a second, later window.
            db.ChangeTracker.Clear();
            var winner = await Find(db, featureKey, ct);
            if (winner is null)
                throw;

            return new EvaluationStart(winner.StartedAtUtc, StartedNow: false);
        }
    }

    private static Task<FeatureEvaluation?> Find(EclipsVaultDbContext db, string featureKey, CancellationToken ct)
        => db.FeatureEvaluations.AsNoTracking().FirstOrDefaultAsync(e => e.FeatureKey == featureKey, ct);
}
