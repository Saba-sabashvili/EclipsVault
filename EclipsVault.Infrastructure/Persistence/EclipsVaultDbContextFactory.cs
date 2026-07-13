using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace EclipsVault.Infrastructure.Persistence;

/// <summary>
/// Design-time factory used only by the EF Core tools (<c>dotnet ef migrations …</c>).
/// It lets the tooling construct the DbContext without booting the web host, so
/// migrations can be generated offline. The connection string here is for design
/// time only — the running application always uses the one from configuration.
/// </summary>
public sealed class EclipsVaultDbContextFactory : IDesignTimeDbContextFactory<EclipsVaultDbContext>
{
    private const string DesignTimeConnection =
        "Server=localhost,1433;Database=EclipsVaultUmbraDb;User Id=sa;Password=Vision1889Academy;TrustServerCertificate=True";

    public EclipsVaultDbContext CreateDbContext(string[] args)
    {
        var connection = Environment.GetEnvironmentVariable("ECLIPSVAULT_DESIGN_CONNECTION") ?? DesignTimeConnection;

        var options = new DbContextOptionsBuilder<EclipsVaultDbContext>()
            .UseSqlServer(connection, sql => sql.MigrationsAssembly(typeof(EclipsVaultDbContextFactory).Assembly.FullName))
            .Options;

        return new EclipsVaultDbContext(options);
    }
}
