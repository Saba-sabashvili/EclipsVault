using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Persistence;

/// <summary>
/// Brings the schema up to date, or refuses to serve on a schema that is not. The schema is owned
/// entirely by the migration files under Persistence/Migrations — no EnsureCreated, no raw DDL.
///
/// This is deliberately separate from <see cref="DbSeeder"/>, and deliberately does nothing in
/// production by default. Applying migrations needs rights to alter every table; serving requests
/// needs rights to read and write rows. Collapsing the two means the vault's own login carries DDL
/// permissions for its entire life, so anyone who reaches the connection string can rewrite the
/// audit tables rather than merely read them — and the app only needed those rights for the few
/// seconds after boot.
///
/// Checking is not the same as applying, so this still verifies: a process serving requests against
/// a schema older than its code is a subtler failure than one that will not start.
/// </summary>
public static class DatabaseMigrator
{
    public static async Task MigrateAsync(
        IServiceProvider services, IHostEnvironment environment, CancellationToken ct = default)
    {
        using var scope = services.CreateScope();
        var sp = scope.ServiceProvider;
        var db = sp.GetRequiredService<EclipsVaultDbContext>();
        var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("EclipsVault.DatabaseMigrator");

        var configuration = sp.GetRequiredService<IConfiguration>();
        var options = configuration.GetSection(DatabaseOptions.SectionName).Get<DatabaseOptions>()
                      ?? new DatabaseOptions();

        var mayApply = environment.IsDevelopment() || options.MigrateOnStartup;

        var pending = (await db.Database.GetPendingMigrationsAsync(ct)).ToList();
        if (pending.Count == 0)
        {
            return;
        }

        if (!mayApply)
        {
            throw new InvalidOperationException(
                $"The database is {pending.Count} migration(s) behind this build ({string.Join(", ", pending)}), and " +
                "this service is not permitted to change the schema. Apply them from your deploy job, with a " +
                "login that holds DDL rights the running vault does not:\n\n" +
                "    dotnet ef database update --project EclipsVault.Infrastructure --startup-project EclipsVault.Web\n\n" +
                "For a single-node install with no deploy pipeline, set Database:MigrateOnStartup=true and accept " +
                "that the vault's own login then needs rights to rewrite every table, including the audit trail.");
        }

        logger.LogInformation("Applying {PendingCount} pending migration(s): {Migrations}",
            pending.Count, string.Join(", ", pending));
        await db.Database.MigrateAsync(ct);
    }
}
