using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Persistence;

/// <summary>
/// Brings the schema up to date. The schema is owned entirely by the migration files under
/// Persistence/Migrations — no EnsureCreated, no raw DDL.
///
/// This is deliberately separate from <see cref="DbSeeder"/>. Applying migrations needs rights to
/// alter every table in the database; serving requests needs rights to read and write rows. Those
/// are different jobs for different identities, and keeping them in one method is what forces the
/// running service to hold DDL permissions it never uses again after startup.
/// </summary>
public static class DatabaseMigrator
{
    public static async Task MigrateAsync(IServiceProvider services, CancellationToken ct = default)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<EclipsVaultDbContext>();
        var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>()
            .CreateLogger("EclipsVault.DatabaseMigrator");

        var pending = (await db.Database.GetPendingMigrationsAsync(ct)).ToList();
        if (pending.Count == 0)
        {
            return;
        }

        logger.LogInformation("Applying {PendingCount} pending migration(s): {Migrations}",
            pending.Count, string.Join(", ", pending));
        await db.Database.MigrateAsync(ct);
    }
}
