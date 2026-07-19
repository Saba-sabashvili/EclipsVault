using System.Text;
using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EclipsVault.Tests.Persistence;

/// <summary>
/// A save that does not commit must leave nothing staged.
///
/// EF keeps a failed SaveChanges pending so it can be retried, but the context is scoped to the
/// request and shared with the audit sink, and SaveChanges flushes everything pending rather than
/// only its caller's rows — so a staged failure waits for the next SaveChanges by anyone at all,
/// which commits it. That let a secret rotation reported as failed come back, carried in by the very
/// audit row written to say it had failed.
///
/// These run the real <see cref="EclipsVaultDbContext"/> against in-memory SQLite: the guarantee is
/// the context's own, so it can be pinned without a database server. The audit interceptor is not
/// wired up here — it stamps the hash chain through <c>sp_getapplock</c> and needs SQL Server — but
/// an audit row staged by the interceptor is an ordinary pending insert, which is what the last test
/// covers.
/// </summary>
public class FailedSaveTests : IDisposable
{
    private const string OriginalValue = "value-before";
    private const string FailedValue = "value-that-failed-to-store";

    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<EclipsVaultDbContext> _options;

    public FailedSaveTests()
    {
        // A held-open in-memory connection: the schema lives as long as the connection does.
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        _options = new DbContextOptionsBuilder<EclipsVaultDbContext>().UseSqlite(_connection).Options;

        using var db = new EclipsVaultDbContext(_options);
        db.Database.EnsureCreated();
    }

    public void Dispose()
    {
        _connection.Dispose();
        GC.SuppressFinalize(this);
    }

    private EclipsVaultDbContext NewContext() => new(_options);

    private static Secret NewSecret(Guid id, string value) => new()
    {
        Id = id,
        Name = "app_probe_password",
        ProjectKey = "PHOENIX",
        Environment = SecretEnvironment.Production,
        Sensitivity = SensitivityLevel.Secret,
        Ciphertext = Encoding.UTF8.GetBytes(value),
        WrappedDek = [1, 2, 3],
        KekId = "test-kek",
        Algorithm = "AES-256-GCM",
        CreatedAtUtc = DateTimeOffset.UtcNow,
        CreatedByUserId = Guid.Empty
    };

    /// <summary>An archived version pointing at no secret — a foreign key violation on save.</summary>
    private static SecretVersion DoomedVersion() => new()
    {
        Id = Guid.NewGuid(),
        SecretId = Guid.NewGuid(),
        VersionNumber = 1,
        Ciphertext = Encoding.UTF8.GetBytes(OriginalValue),
        WrappedDek = [1, 2, 3],
        KekId = "test-kek",
        Algorithm = "AES-256-GCM",
        ArchivedAtUtc = DateTimeOffset.UtcNow,
        ArchivedBy = "tester"
    };

    private async Task<Guid> SeedAsync()
    {
        var id = Guid.NewGuid();
        await using var db = NewContext();
        db.Secrets.Add(NewSecret(id, OriginalValue));
        await db.SaveChangesAsync();
        return id;
    }

    /// <summary>Stages a rotation that cannot commit, and returns the context still holding it.</summary>
    private async Task<(EclipsVaultDbContext Db, Secret Secret, SecretVersion Version)> StageDoomedRotationAsync(Guid id)
    {
        var db = NewContext();
        var secret = await db.Secrets.FirstAsync(s => s.Id == id);
        var version = DoomedVersion();

        secret.Ciphertext = Encoding.UTF8.GetBytes(FailedValue);
        secret.UpdatedAtUtc = DateTimeOffset.UtcNow;
        db.SecretVersions.Add(version);
        db.Secrets.Update(secret);

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        return (db, secret, version);
    }

    [Fact]
    public async Task A_failed_save_leaves_the_tracker_matching_the_database()
    {
        var (db, secret, version) = await StageDoomedRotationAsync(await SeedAsync());
        await using var _ = db;

        Assert.Equal(EntityState.Unchanged, db.Entry(secret).State);
        Assert.Equal(EntityState.Detached, db.Entry(version).State);
    }

    [Fact]
    public async Task A_failed_save_rewinds_the_entity_itself_not_just_its_tracker_state()
    {
        // The caller still holds this instance and acts on what it sees — a rotation that put an
        // upstream password back while holding the new one would restore the wrong value.
        var (db, secret, _) = await StageDoomedRotationAsync(await SeedAsync());
        await using var _db = db;

        Assert.Equal(OriginalValue, Encoding.UTF8.GetString(secret.Ciphertext));
    }

    [Fact]
    public async Task A_failed_save_does_not_come_back_when_someone_else_saves()
    {
        // The bug this exists for: the audit sink shares this context, so its SaveChanges committed
        // the rotation that had just failed — the drift row and the change it denied, in one commit.
        var id = await SeedAsync();
        var (db, _, _) = await StageDoomedRotationAsync(id);
        await using var _db = db;

        db.AuditLogs.Add(NewAuditRow(id, AuditAction.SecretUpstreamRotationDrifted));
        await db.SaveChangesAsync();

        await using var verify = NewContext();
        var stored = await verify.Secrets.AsNoTracking().FirstAsync(s => s.Id == id);
        Assert.Equal(OriginalValue, Encoding.UTF8.GetString(stored.Ciphertext));
        Assert.False(await verify.SecretVersions.AsNoTracking().AnyAsync(v => v.SecretId == id));
    }

    [Fact]
    public async Task An_audit_row_staged_with_a_failed_save_is_discarded_with_it()
    {
        // The interceptor injects its audit row into the same batch. When the batch failed, the row
        // stayed staged and the next save stamped it into the chain for real — a correctly hashed
        // entry for a change that was rolled back.
        var id = await SeedAsync();

        await using var db = NewContext();
        var secret = await db.Secrets.FirstAsync(s => s.Id == id);
        secret.Ciphertext = Encoding.UTF8.GetBytes(FailedValue);
        db.Secrets.Update(secret);
        db.SecretVersions.Add(DoomedVersion());
        db.AuditLogs.Add(NewAuditRow(id, AuditAction.SecretUpdated)); // stands in for the injected row

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());

        Assert.DoesNotContain(db.ChangeTracker.Entries<AuditLog>(), e => e.State == EntityState.Added);

        await db.SaveChangesAsync(); // nothing left to commit
        await using var verify = NewContext();
        Assert.False(await verify.AuditLogs.AsNoTracking().AnyAsync(a => a.ResourceId == id));
    }

    [Fact]
    public async Task A_save_that_commits_is_untouched()
    {
        var id = await SeedAsync();

        await using (var db = NewContext())
        {
            var secret = await db.Secrets.FirstAsync(s => s.Id == id);
            secret.Ciphertext = Encoding.UTF8.GetBytes("value-after");
            db.Secrets.Update(secret);
            db.SecretVersions.Add(new SecretVersion
            {
                Id = Guid.NewGuid(),
                SecretId = id,
                VersionNumber = 1,
                Ciphertext = Encoding.UTF8.GetBytes(OriginalValue),
                WrappedDek = [1, 2, 3],
                KekId = "test-kek",
                Algorithm = "AES-256-GCM",
                ArchivedAtUtc = DateTimeOffset.UtcNow,
                ArchivedBy = "tester"
            });
            await db.SaveChangesAsync();
        }

        await using var verify = NewContext();
        var stored = await verify.Secrets.AsNoTracking().FirstAsync(s => s.Id == id);
        Assert.Equal("value-after", Encoding.UTF8.GetString(stored.Ciphertext));
        Assert.Equal(1, await verify.SecretVersions.AsNoTracking().CountAsync(v => v.SecretId == id));
    }

    private static AuditLog NewAuditRow(Guid resourceId, AuditAction action) => new()
    {
        Id = Guid.NewGuid(),
        TimestampUtc = DateTimeOffset.UtcNow,
        Username = "tester",
        SourceIp = "::1",
        Action = action,
        ResourceType = nameof(Secret),
        ResourceId = resourceId,
        ResourceName = "app_probe_password"
    };
}
