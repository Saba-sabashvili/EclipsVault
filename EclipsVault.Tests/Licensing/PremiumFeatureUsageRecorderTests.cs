using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Core.Domain.Exceptions;
using EclipsVault.Infrastructure.Persistence;
using EclipsVault.Infrastructure.Security.Licensing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace EclipsVault.Tests.Licensing;

public class PremiumFeatureUsageRecorderTests
{
    private sealed class FakeLicense : ILicenseState
    {
        public LicenseStatus Status { get; init; } = LicenseStatus.Valid;
        public LicenseClaims? Claims { get; init; }
        public string Message { get; init; } = "";
        public HashSet<string> Allowed { get; init; } = new(StringComparer.Ordinal);
        public bool Allows(string feature) => Allowed.Contains(feature);
    }

    private sealed class NullActor : IAuditContext
    {
        public Guid? UserId => null;
        public string? Username => null;
        public string? SourceIp => null;
    }

    private sealed class ThrowingAuditSink : IAuditSink
    {
        public Task WriteAsync(AuditEntry entry, CancellationToken ct)
            => throw new AuditWriteFailedException("boom");
    }

    // Writes through the real fail-closed AuditSink/AuditGroupCommitter (as the app does), then counts
    // the LicenseFeatureUnlicensed rows recorded for a feature after N RecordUseAsync calls.
    private static async Task<int> RowsAfter(ILicenseState license, string feature, int calls)
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
            var recorder = new PremiumFeatureUsageRecorder(
                license,
                provider.GetRequiredService<IServiceScopeFactory>(),
                NullLogger<PremiumFeatureUsageRecorder>.Instance);

            for (var i = 0; i < calls; i++)
                await recorder.RecordUseAsync(feature, CancellationToken.None);

            await using var read = provider.CreateAsyncScope();
            return await read.ServiceProvider.GetRequiredService<EclipsVaultDbContext>()
                .AuditLogs.CountAsync(a =>
                    a.Action == AuditAction.LicenseFeatureUnlicensed
                    && a.ResourceName == feature
                    && a.ResourceType == "License"
                    && !a.IsCritical
                    && a.Username == "system");
        }
        finally
        {
            await committer.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task Unlicensed_use_writes_one_soft_row()
        => Assert.Equal(1, await RowsAfter(new FakeLicense(), LicenseFeatures.DynamicSecrets, calls: 1));

    [Fact]
    public async Task Repeated_use_is_deduplicated_to_one_row()
        => Assert.Equal(1, await RowsAfter(new FakeLicense(), LicenseFeatures.DynamicSecrets, calls: 5));

    [Fact]
    public async Task Licensed_use_writes_no_row()
    {
        var license = new FakeLicense { Allowed = new(StringComparer.Ordinal) { LicenseFeatures.DynamicSecrets } };
        Assert.Equal(0, await RowsAfter(license, LicenseFeatures.DynamicSecrets, calls: 3));
    }

    [Fact]
    public async Task Audit_write_failure_is_swallowed()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddScoped<IAuditSink, ThrowingAuditSink>();
        await using var provider = services.BuildServiceProvider();

        var recorder = new PremiumFeatureUsageRecorder(
            new FakeLicense(),
            provider.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<PremiumFeatureUsageRecorder>.Instance);

        // Must not throw.
        await recorder.RecordUseAsync(LicenseFeatures.Kms, CancellationToken.None);
    }
}
