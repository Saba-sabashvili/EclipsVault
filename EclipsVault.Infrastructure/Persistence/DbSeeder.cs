using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Persistence;

/// <summary>
/// Creates the schema and seeds development data: two staff accounts, sample project
/// secrets, one short-TTL secret to demonstrate the lifecycle shredder, and the
/// honey-token decoys used for intrusion detection.
/// </summary>
public static class DbSeeder
{
    public static async Task SeedAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var sp = scope.ServiceProvider;

        var db = sp.GetRequiredService<EclipsVaultDbContext>();
        var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("EclipsVault.DbSeeder");

        // Apply any pending EF Core migrations. The schema is owned entirely by the
        // migration files under Persistence/Migrations — no EnsureCreated, no raw DDL.
        await db.Database.MigrateAsync();

        var clock = sp.GetRequiredService<TimeProvider>();
        var now = clock.GetUtcNow();

        if (!await db.Users.AnyAsync())
        {
            var hasher = sp.GetRequiredService<IPasswordHasher>();
            var configuration = sp.GetRequiredService<IConfiguration>();

            var adminPassword = configuration["Seed:AdminPassword"] ?? "ChangeMe!Umbra#2026-Admin";
            var devPassword = configuration["Seed:DevPassword"] ?? "ChangeMe!Umbra#2026-Dev";

            var adminHash = hasher.Hash(adminPassword);
            var devHash = hasher.Hash(devPassword);

            db.Users.AddRange(
                new User
                {
                    Id = Guid.NewGuid(),
                    Username = "vault-admin",
                    DisplayName = "Vault Administrator",
                    Email = "vault-admin@eclipsvault.local",
                    PasswordHash = adminHash.Hash,
                    PasswordSalt = adminHash.Salt,
                    Clearance = ClearanceLevel.TopSecret,
                    ProjectKey = "GLOBAL",
                    CreatedAtUtc = now
                },
                new User
                {
                    Id = Guid.NewGuid(),
                    Username = "dev-user",
                    DisplayName = "Dev User",
                    Email = "dev-user@eclipsvault.local",
                    PasswordHash = devHash.Hash,
                    PasswordSalt = devHash.Salt,
                    Clearance = ClearanceLevel.Standard,
                    ProjectKey = "PHOENIX",
                    CreatedAtUtc = now
                });

            await db.SaveChangesAsync();
            logger.LogInformation("Seeded staff accounts {AdminUser} and {DevUser} (TOTP enrollment happens on first sign-in)",
                "vault-admin", "dev-user");
        }

        if (!await db.Secrets.AnyAsync())
        {
            var engine = sp.GetRequiredService<ICryptoEngineFactory>().Create();

            db.Secrets.AddRange(
                SealSecret(engine, now, "Phoenix_Dev_Database_Password", "PHOENIX", SecretEnvironment.Development,
                    SensitivityLevel.Internal, "Server=phx-dev-sql;Database=Phoenix;User Id=phx_app;Password=dev-only-Sample!42"),
                SealSecret(engine, now, "Phoenix_Staging_Api_Key", "PHOENIX", SecretEnvironment.Staging,
                    SensitivityLevel.Confidential, "phx_stg_api_9f83b2e1c4d5460fb7a1"),
                SealSecret(engine, now, "Phoenix_Ephemeral_Deploy_Token", "PHOENIX", SecretEnvironment.Development,
                    SensitivityLevel.Internal, "deploy-token-expires-soon-5f6e7d8c",
                    expiresAtUtc: now.AddMinutes(5)),

                // Honey-token decoys: realistic bait. Any by-id read trips the intrusion response.
                SealSecret(engine, now, "Production_AWS_Root_Key", "GLOBAL", SecretEnvironment.Production,
                    SensitivityLevel.TopSecret, "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    isHoneyToken: true),
                SealSecret(engine, now, "Global_SQL_SA_Password", "GLOBAL", SecretEnvironment.Production,
                    SensitivityLevel.TopSecret, "Sup3r$ecretS4-Pr0d-2026!",
                    isHoneyToken: true));

            await db.SaveChangesAsync();
            logger.LogInformation("Seeded sample secrets, one short-TTL secret, and {HoneyTokenCount} honey-token decoys", 2);
        }
    }

    private static Secret SealSecret(
        ICryptoEngine engine,
        DateTimeOffset now,
        string name,
        string projectKey,
        SecretEnvironment environment,
        SensitivityLevel sensitivity,
        string value,
        DateTimeOffset? expiresAtUtc = null,
        bool isHoneyToken = false)
    {
        var sealedSecret = engine.Seal(System.Text.Encoding.UTF8.GetBytes(value));
        return new Secret
        {
            Id = Guid.NewGuid(),
            Name = name,
            ProjectKey = projectKey,
            Environment = environment,
            Sensitivity = sensitivity,
            Ciphertext = sealedSecret.Ciphertext,
            WrappedDek = sealedSecret.WrappedDek,
            KekId = sealedSecret.KekId,
            Algorithm = sealedSecret.Algorithm,
            IsHoneyToken = isHoneyToken,
            CreatedAtUtc = now,
            ExpiresAtUtc = expiresAtUtc
        };
    }
}
