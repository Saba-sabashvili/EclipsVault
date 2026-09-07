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

    /// <summary>
    /// A window store under the test's control. <see cref="Start"/> null means the capability has
    /// never been exercised, so the next <see cref="GetOrStartAsync"/> opens the window.
    /// </summary>
    private sealed class FakeWindows : IEvaluationWindowStore
    {
        public DateTimeOffset? Start { get; set; }
        public Exception? Fail { get; set; }
        public int TimesOpened { get; private set; }

        public Task<DateTimeOffset?> PeekAsync(string featureKey, CancellationToken ct)
            => Task.FromResult(Start);

        public Task<EvaluationStart> GetOrStartAsync(string featureKey, CancellationToken ct)
        {
            if (Fail is not null)
                throw Fail;

            if (Start is null)
            {
                Start = DateTimeOffset.UtcNow;
                TimesOpened++;
                return Task.FromResult(new EvaluationStart(Start.Value, StartedNow: true));
            }

            return Task.FromResult(new EvaluationStart(Start.Value, StartedNow: false));
        }
    }

    /// <summary>A window that opened long enough ago that the evaluation period has run out.</summary>
    private static FakeWindows Expired() =>
        new() { Start = DateTimeOffset.UtcNow.AddDays(-(EvaluationWindow.Days + 1)) };

    /// <summary>A window that opened today, so the evaluation period is still running.</summary>
    private static FakeWindows Active() => new() { Start = DateTimeOffset.UtcNow };

    private sealed class ThrowingAuditSink : IAuditSink
    {
        public Task WriteAsync(AuditEntry entry, CancellationToken ct)
            => throw new AuditWriteFailedException("boom");
    }

    /// <summary>
    /// Anything that is not the sink's own failure signal — resolving a service or creating a scope
    /// during shutdown, for instance, raises <see cref="ObjectDisposedException"/>. The recorder sits
    /// on the secret path, so this must be swallowed exactly like an audit failure.
    /// </summary>
    private sealed class UnexpectedlyThrowingAuditSink : IAuditSink
    {
        public Task WriteAsync(AuditEntry entry, CancellationToken ct)
            => throw new ObjectDisposedException(nameof(UnexpectedlyThrowingAuditSink));
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
                Expired(),
                TimeProvider.System,
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
            Expired(),
            TimeProvider.System,
            provider.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<PremiumFeatureUsageRecorder>.Instance);

        // Must not throw.
        await recorder.RecordUseAsync(LicenseFeatures.Kms, CancellationToken.None);
    }

    /// <summary>
    /// The class promises it never throws, because it runs on the path that serves secrets. That has
    /// to hold for every failure, not only the audit sink's own — a narrower catch would let a
    /// shutdown-time ObjectDisposedException travel up into the operation and make a licensing
    /// reminder capable of failing a reveal.
    /// </summary>
    [Fact]
    public async Task An_unexpected_failure_is_swallowed_too()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddScoped<IAuditSink, UnexpectedlyThrowingAuditSink>();
        await using var provider = services.BuildServiceProvider();

        var recorder = new PremiumFeatureUsageRecorder(
            new FakeLicense(),
            Expired(),
            TimeProvider.System,
            provider.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<PremiumFeatureUsageRecorder>.Instance);

        // Must not throw — licensing never blocks the vault.
        await recorder.RecordUseAsync(LicenseFeatures.Kms, CancellationToken.None);
    }

    private sealed class NoOpAuditSink : IAuditSink
    {
        public Task WriteAsync(AuditEntry entry, CancellationToken ct) => Task.CompletedTask;
    }

    private static PremiumFeatureUsageRecorder RecorderWith(
        ILicenseState license, IEvaluationWindowStore? windows = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddScoped<IAuditSink, NoOpAuditSink>();
        var provider = services.BuildServiceProvider();
        return new PremiumFeatureUsageRecorder(
            license, windows ?? Expired(), TimeProvider.System,
            provider.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<PremiumFeatureUsageRecorder>.Instance);
    }

    [Fact]
    public async Task Require_throws_for_a_gated_feature_once_the_evaluation_period_has_ended()
    {
        var recorder = RecorderWith(new FakeLicense(), Expired()); // grants nothing, window spent
        await Assert.ThrowsAsync<PremiumFeatureNotLicensedException>(
            () => recorder.RequireAsync(LicenseFeatures.DynamicSecrets, CancellationToken.None));
    }

    [Fact]
    public async Task Require_returns_for_a_gated_feature_when_licensed()
    {
        var license = new FakeLicense { Allowed = new(StringComparer.Ordinal) { LicenseFeatures.ManagedRotation } };
        await RecorderWith(license).RequireAsync(LicenseFeatures.ManagedRotation, CancellationToken.None); // no throw
    }

    [Fact]
    public async Task Require_does_not_throw_for_a_non_gated_feature_when_unlicensed()
    {
        // Attestation is soft: RequireAsync must record-and-return, never throw.
        await RecorderWith(new FakeLicense()).RequireAsync(LicenseFeatures.AuditAttestation, CancellationToken.None);
    }

    [Fact]
    public async Task Require_throws_every_call_even_after_the_row_is_deduplicated()
    {
        var recorder = RecorderWith(new FakeLicense(), Expired());
        await Assert.ThrowsAsync<PremiumFeatureNotLicensedException>(
            () => recorder.RequireAsync(LicenseFeatures.DynamicSecrets, CancellationToken.None));
        await Assert.ThrowsAsync<PremiumFeatureNotLicensedException>(
            () => recorder.RequireAsync(LicenseFeatures.DynamicSecrets, CancellationToken.None));
    }

    /// <summary>A clock the test moves, so an evaluation period can be spent without waiting 30 days.</summary>
    private sealed class MovableTime : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }

    [Fact]
    public async Task Require_allows_a_gated_feature_during_the_evaluation_period()
    {
        // The licence grants 30 days of production use without a key; the gate must honour it.
        await RecorderWith(new FakeLicense(), Active())
            .RequireAsync(LicenseFeatures.DynamicSecrets, CancellationToken.None); // no throw
    }

    [Fact]
    public async Task Require_opens_the_window_on_first_use_and_allows()
    {
        var windows = new FakeWindows(); // never exercised
        await RecorderWith(new FakeLicense(), windows)
            .RequireAsync(LicenseFeatures.DynamicSecrets, CancellationToken.None);

        Assert.Equal(1, windows.TimesOpened);
        Assert.NotNull(windows.Start);
    }

    [Fact]
    public async Task The_window_is_opened_once_however_many_times_the_feature_is_used()
    {
        var windows = new FakeWindows();
        var recorder = RecorderWith(new FakeLicense(), windows);

        for (var i = 0; i < 5; i++)
            await recorder.RequireAsync(LicenseFeatures.DynamicSecrets, CancellationToken.None);

        Assert.Equal(1, windows.TimesOpened);
    }

    /// <summary>
    /// A licensing lookup that cannot reach the database must never become the operator's outage.
    /// An unresolvable window therefore grants the capability; the direction of this failure is
    /// deliberate and is what keeps a licence check from taking a vault down.
    /// </summary>
    [Fact]
    public async Task Require_allows_when_the_window_store_fails()
    {
        var windows = new FakeWindows { Fail = new InvalidOperationException("database is gone") };
        await RecorderWith(new FakeLicense(), windows)
            .RequireAsync(LicenseFeatures.DynamicSecrets, CancellationToken.None); // no throw
    }

    /// <summary>
    /// The two rows a gated feature writes — the window opening, and the refusal up to 30 days later
    /// — are separate events about the same feature. Deduplicating on the feature alone would let the
    /// first row swallow the second and leave the refusal unrecorded.
    /// </summary>
    [Fact]
    public async Task Opening_the_window_does_not_suppress_the_later_refusal_row()
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
            var clock = new MovableTime();
            var recorder = new PremiumFeatureUsageRecorder(
                new FakeLicense(),
                new FakeWindows(),
                clock,
                provider.GetRequiredService<IServiceScopeFactory>(),
                NullLogger<PremiumFeatureUsageRecorder>.Instance);

            // First use opens the window and is allowed.
            await recorder.RequireAsync(LicenseFeatures.DynamicSecrets, CancellationToken.None);

            // Spend it, then use the feature again.
            clock.Advance(TimeSpan.FromDays(EvaluationWindow.Days + 1));
            await Assert.ThrowsAsync<PremiumFeatureNotLicensedException>(
                () => recorder.RequireAsync(LicenseFeatures.DynamicSecrets, CancellationToken.None));

            await using var read = provider.CreateAsyncScope();
            var db = read.ServiceProvider.GetRequiredService<EclipsVaultDbContext>();

            Assert.Equal(1, await db.AuditLogs.CountAsync(a =>
                a.Action == AuditAction.LicenseEvaluationStarted
                && a.ResourceName == LicenseFeatures.DynamicSecrets));
            Assert.Equal(1, await db.AuditLogs.CountAsync(a =>
                a.Action == AuditAction.LicenseFeatureBlocked
                && a.ResourceName == LicenseFeatures.DynamicSecrets));
        }
        finally
        {
            await committer.StopAsync(CancellationToken.None);
        }
    }
}
