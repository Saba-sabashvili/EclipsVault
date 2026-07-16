using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace EclipsVault.Infrastructure.Persistence;

/// <summary>
/// Design-time factory used only by the EF Core tools (<c>dotnet ef migrations …</c>).
/// It lets the tooling construct the DbContext without booting the web host, so
/// migrations can be generated offline. The connection string here is for design
/// time only — the running application always uses the one from configuration.
///
/// <para>Which engine the tools target comes from <c>ECLIPSVAULT_DESIGN_PROVIDER</c>, because
/// migrations are generated per provider and each engine's set lives in its own assembly:
/// <code>
/// ECLIPSVAULT_DESIGN_PROVIDER=Postgres \
/// ECLIPSVAULT_DESIGN_CONNECTION="Host=localhost;Port=5433;Database=EclipsVaultUmbraDb;Username=postgres;Password=…" \
/// dotnet ef migrations add &lt;Name&gt; -p EclipsVault.Migrations.Postgres -s EclipsVault.Infrastructure
/// </code>
/// Adding a migration for one engine means adding it for both, or the two schemas drift.</para>
/// </summary>
public sealed class EclipsVaultDbContextFactory : IDesignTimeDbContextFactory<EclipsVaultDbContext>
{
    private const string DesignTimeSqlServerConnection =
        "Server=localhost,1433;Database=EclipsVaultUmbraDb;User Id=sa;Password=Vision1889Academy;TrustServerCertificate=True";

    private const string DesignTimePostgresConnection =
        "Host=localhost;Port=5433;Database=EclipsVaultUmbraDb;Username=postgres;Password=Vision1889Academy";

    public EclipsVaultDbContext CreateDbContext(string[] args)
    {
        var provider = Environment.GetEnvironmentVariable("ECLIPSVAULT_DESIGN_PROVIDER") ?? DatabaseProvider.SqlServer;
        var isPostgres = DatabaseProvider.IsPostgres(provider);

        var connection = Environment.GetEnvironmentVariable("ECLIPSVAULT_DESIGN_CONNECTION")
                         ?? (isPostgres ? DesignTimePostgresConnection : DesignTimeSqlServerConnection);

        var builder = new DbContextOptionsBuilder<EclipsVaultDbContext>();
        if (isPostgres)
        {
            builder.UseNpgsql(connection, npgsql => npgsql.MigrationsAssembly(DatabaseProvider.PostgresMigrationsAssembly));
        }
        else
        {
            builder.UseSqlServer(connection, sql => sql.MigrationsAssembly(typeof(EclipsVaultDbContextFactory).Assembly.FullName));
        }

        return new EclipsVaultDbContext(builder.Options);
    }
}
