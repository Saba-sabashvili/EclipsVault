using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Infrastructure.Persistence;
using EclipsVault.Infrastructure.Workers;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace EclipsVault.Tests.Licensing;

/// <summary>
/// The startup license check writes its audit row through the real fail-closed <see cref="AuditSink"/>
/// / <see cref="AuditGroupCommitter"/>. Because the committer only drains once started, these run it
/// exactly as the app does — started first — and each test completing at all is the proof the write
/// does not hang waiting on a drain that never comes.
/// </summary>
public class LicenseStartupCheckTests
{
    private sealed class FakeLicense : ILicenseState
    {
        public LicenseStatus Status { get; init; }
        public LicenseClaims? Claims { get; init; }
        public string Message { get; init; } = "";
        public bool Allows(string feature) => false;
    }

    private sealed class NullActor : IAuditContext
    {
        public Guid? UserId => null;
        public string? Username => null;
        public string? SourceIp => null;
    }

    private sealed class FakeEnv : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "test";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }

    private static async Task<int> SoftRowsAfterStartup(string environment, LicenseStatus status)
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(TimeProvider.System);
        services.AddDbContext<EclipsVaultDbContext>(o => o.UseSqlite(connection));
        services.AddSingleton<AuditGroupCommitter>();
        services.AddScoped<IAuditContext, NullActor>();
        services.AddScoped<IAuditSink, AuditSink>();
        await using var provider = services.BuildServiceProvider();

        await using (var setup = provider.CreateAsyncScope())
            await setup.ServiceProvider.GetRequiredService<EclipsVaultDbContext>().Database.EnsureCreatedAsync();

        var committer = provider.GetRequiredService<AuditGroupCommitter>();
        await committer.StartAsync(CancellationToken.None);
        try
        {
            var check = new LicenseStartupCheck(
                new FakeLicense { Status = status, Message = status.ToString() },
                new FakeEnv { EnvironmentName = environment },
                provider.GetRequiredService<IServiceScopeFactory>(),
                NullLogger<LicenseStartupCheck>.Instance);

            await check.StartAsync(CancellationToken.None);

            await using var read = provider.CreateAsyncScope();
            return await read.ServiceProvider.GetRequiredService<EclipsVaultDbContext>()
                .AuditLogs.CountAsync(a => a.Action == AuditAction.LicenseInvalidProductionUse && !a.IsCritical);
        }
        finally
        {
            await committer.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task Unlicensed_in_production_writes_one_soft_audit_row()
    {
        Assert.Equal(1, await SoftRowsAfterStartup(Environments.Production, LicenseStatus.Missing));
    }

    [Fact]
    public async Task Development_writes_no_row_even_when_unlicensed()
    {
        Assert.Equal(0, await SoftRowsAfterStartup(Environments.Development, LicenseStatus.Missing));
    }

    [Fact]
    public async Task A_valid_license_in_production_writes_no_row()
    {
        Assert.Equal(0, await SoftRowsAfterStartup(Environments.Production, LicenseStatus.Valid));
    }
}
