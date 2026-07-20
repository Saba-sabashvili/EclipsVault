# License Feature Gating (Soft Surfacing) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every Max-only feature produce a consistent, auditable signal when it runs unlicensed or beyond the current tier, without ever changing behavior.

**Architecture:** Two mechanisms. (A) Config-toggled features (KMS, Redis HA, SSO) are detected once at startup by a single `ConfiguredPremiumFeatures` source, consumed by the banner builder and by an expanded `LicenseStartupCheck` that records a soft audit row naming the beyond-tier features. (B) On-demand features (dynamic secrets, managed rotation, audit attestation) call a new soft `IPremiumFeatureUsage` recorder at their call site; the recorder writes one deduplicated audit row per feature per process and never throws.

**Tech Stack:** .NET 10, ASP.NET Core, EF Core (SQL Server / PostgreSQL; SQLite in tests), xUnit. Solution file is `EclipsVault.slnx` (NOT `.sln`).

## Global Constraints

- **Solution file is `EclipsVault.slnx`.** Build: `dotnet build EclipsVault.slnx -c Debug`. Test: `dotnet test EclipsVault.slnx`.
- **Clean Architecture.** `EclipsVault.Core` is BCL-only (zero NuGet) and depends on nothing; `Infrastructure` → `Core`; `Web` → `Infrastructure` → `Core`. New Core files may reference only Core abstractions.
- **Warnings are errors in production code.** `Directory.Build.props` sets `TreatWarningsAsErrors=true` and `CodeAnalysisTreatWarningsAsErrors=true` for Core/Infra/Web. New production code must be warning-clean (no unused fields/params/usings that trip an active analyzer; mirror the existing `await` style — the codebase does NOT use `ConfigureAwait`). The **Tests** project sets `TreatWarningsAsErrors=false`.
- **Global usings.** `EclipsVault.Core.Application.*` feature namespaces (incl. `Abstractions`) are globally imported in Core/Infra/Web — **except `EclipsVault.Core.Application.Licensing`, which always needs an explicit `using`.** `EclipsVault.Core.Domain.Enums` and `.Domain.Exceptions` are NOT global (add explicit usings). The **Tests** project has NO global usings — add every `using` explicitly.
- **Invariants (verify in tests):** licensing never blocks the vault and is never on the secret read/decrypt path; behavior is identical licensed vs unlicensed; the recorder never throws (swallow `AuditWriteFailedException`); Development is never nagged or recorded; on-demand signals dedupe to once per feature per process.
- **Feature keys** are the existing constants in `EclipsVault.Core/Application/Licensing/LicenseFeatures.cs`: `Sso="sso"`, `Kms="kms"`, `RedisHa="redis-ha"`, `DynamicSecrets="dynamic-secrets"`, `ManagedRotation="managed-rotation"`, `AuditAttestation="audit-attestation"`.
- **Soft-audit row shape** (mirror `LicenseStartupCheck`): `ResourceType="License"`, `IsCritical=false`, `ActorUsername="system"`.
- **New audit action value:** `LicenseFeatureUnlicensed = 201` (the existing `LicenseInvalidProductionUse = 200` is retained for the whole-license-invalid case).

## File Structure

**New (production):**
- `EclipsVault.Core/Application/Abstractions/IPremiumFeatureUsage.cs` — the soft usage-recorder abstraction.
- `EclipsVault.Infrastructure/Security/Licensing/PremiumFeatureUsageRecorder.cs` — dedup + scoped soft audit write.
- `EclipsVault.Infrastructure/Security/Licensing/ConfiguredPremiumFeatures.cs` — single source of config-active premium keys.

**New (tests):**
- `EclipsVault.Tests/TestDoubles/RecordingPremiumFeatureUsage.cs` — shared recording fake.
- `EclipsVault.Tests/Licensing/ConfiguredPremiumFeaturesTests.cs`
- `EclipsVault.Tests/Licensing/PremiumFeatureUsageRecorderTests.cs`
- `EclipsVault.Tests/Auditing/AuditCheckpointServiceTests.cs`

**Modified:**
- `EclipsVault.Core/Domain/Enums/AuditAction.cs` — add `LicenseFeatureUnlicensed = 201`.
- `EclipsVault.Core/Application/Activity/ActivityDescriber.cs` — add a case for the new action.
- `EclipsVault.Infrastructure/DependencyInjection.cs` — register the detector + recorder.
- `EclipsVault.Web/Program.cs` — banner builder reads the detector.
- `EclipsVault.Infrastructure/Workers/LicenseStartupCheck.cs` — expand trigger + new ctor param.
- `EclipsVault.Core/Application/DynamicSecrets/DynamicSecretService.cs` — ctor param + call site.
- `EclipsVault.Core/Application/Secrets/SecretService.cs` — ctor param + call site.
- `EclipsVault.Infrastructure/Auditing/AuditCheckpointService.cs` — ctor param + call site.
- Test files: `ActivityDescriberTests.cs`, `LicenseStartupCheckTests.cs`, `DynamicSecrets/DynamicSecretServiceTests.cs`, `Secrets/ManagedRotationTests.cs`.

---

### Task 1: Add the `LicenseFeatureUnlicensed` audit action + describer case

**Files:**
- Modify: `EclipsVault.Core/Domain/Enums/AuditAction.cs`
- Modify: `EclipsVault.Core/Application/Activity/ActivityDescriber.cs`
- Test: `EclipsVault.Tests/Activity/ActivityDescriberTests.cs`

**Interfaces:**
- Produces: `AuditAction.LicenseFeatureUnlicensed` (enum value `201`), used by Tasks 4 and 2.

- [ ] **Step 1: Write the failing test**

Add to `EclipsVault.Tests/Activity/ActivityDescriberTests.cs` (inside the existing test class; add `using EclipsVault.Core.Domain.Enums;` and `using EclipsVault.Core.Application.Activity;` at the top if not present):

```csharp
[Fact]
public void Describes_the_unlicensed_premium_feature_action()
{
    var description = ActivityDescriber.Describe(AuditAction.LicenseFeatureUnlicensed);

    Assert.Equal(
        new ActivityDescription(
            ActivityCategory.Administration,
            "Used a premium feature without a license",
            ActivitySeverity.Notable),
        description);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test EclipsVault.slnx --filter "FullyQualifiedName~ActivityDescriberTests.Describes_the_unlicensed_premium_feature_action"`
Expected: build/compile error — `AuditAction` does not contain `LicenseFeatureUnlicensed`.

- [ ] **Step 3: Add the enum value**

In `EclipsVault.Core/Domain/Enums/AuditAction.cs`, immediately after the `LicenseInvalidProductionUse = 200` member (the last member; add a comma after it), add:

```csharp
    LicenseInvalidProductionUse = 200,

    /// <summary>
    /// A Max-only feature was exercised on a vault whose license does not grant it (a Community/
    /// unlicensed deployment, or a feature switched on beyond the current tier). Soft and
    /// deduplicated — a licensing reminder, never a restriction and never a security event.
    /// </summary>
    LicenseFeatureUnlicensed = 201
```

- [ ] **Step 4: Add the describer case**

In `EclipsVault.Core/Application/Activity/ActivityDescriber.cs`, in the `Describe` switch, next to the existing licensing case (`AuditAction.LicenseInvalidProductionUse => ...`), add:

```csharp
        AuditAction.LicenseFeatureUnlicensed => new(ActivityCategory.Administration, "Used a premium feature without a license", ActivitySeverity.Notable),
```

- [ ] **Step 5: Run test to verify it passes**

Run: `dotnet test EclipsVault.slnx --filter "FullyQualifiedName~ActivityDescriberTests.Describes_the_unlicensed_premium_feature_action"`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add EclipsVault.Core/Domain/Enums/AuditAction.cs EclipsVault.Core/Application/Activity/ActivityDescriber.cs EclipsVault.Tests/Activity/ActivityDescriberTests.cs
git commit -m "feat: add LicenseFeatureUnlicensed audit action"
```

---

### Task 2: `IPremiumFeatureUsage` + `PremiumFeatureUsageRecorder`

**Files:**
- Create: `EclipsVault.Core/Application/Abstractions/IPremiumFeatureUsage.cs`
- Create: `EclipsVault.Infrastructure/Security/Licensing/PremiumFeatureUsageRecorder.cs`
- Modify: `EclipsVault.Infrastructure/DependencyInjection.cs`
- Test: `EclipsVault.Tests/Licensing/PremiumFeatureUsageRecorderTests.cs`

**Interfaces:**
- Consumes: `AuditAction.LicenseFeatureUnlicensed` (Task 1); `ILicenseState`, `IAuditSink`, `AuditEntry`, `AuditWriteFailedException` (existing).
- Produces: `IPremiumFeatureUsage.RecordUseAsync(string featureKey, CancellationToken ct) : Task` — consumed by Tasks 5, 6, 7.

- [ ] **Step 1: Create the abstraction**

Create `EclipsVault.Core/Application/Abstractions/IPremiumFeatureUsage.cs`:

```csharp
namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Records that a premium (Max-only) feature was exercised. Implementations are soft: when the
/// current license already grants the feature they do nothing; otherwise they surface a single
/// deduplicated audit line and return. They never throw and never change the caller's behaviour —
/// licensing must never block the vault.
/// </summary>
public interface IPremiumFeatureUsage
{
    /// <summary>
    /// Note a use of <paramref name="featureKey"/> (a <c>LicenseFeatures</c> constant). A no-op when
    /// the feature is licensed; otherwise records one soft audit line per feature per process.
    /// </summary>
    Task RecordUseAsync(string featureKey, CancellationToken ct);
}
```

- [ ] **Step 2: Write the failing tests**

Create `EclipsVault.Tests/Licensing/PremiumFeatureUsageRecorderTests.cs`:

```csharp
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
                .AuditLogs.CountAsync(a => a.Action == AuditAction.LicenseFeatureUnlicensed && a.ResourceName == feature);
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `dotnet test EclipsVault.slnx --filter "FullyQualifiedName~PremiumFeatureUsageRecorderTests"`
Expected: build/compile error — `PremiumFeatureUsageRecorder` does not exist.

- [ ] **Step 4: Create the recorder**

Create `EclipsVault.Infrastructure/Security/Licensing/PremiumFeatureUsageRecorder.cs`:

```csharp
using System.Collections.Concurrent;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Core.Domain.Exceptions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Security.Licensing;

/// <summary>
/// Soft, deduplicated recorder for premium-feature use on an unlicensed/under-tier vault. If the
/// license already grants the feature it does nothing. Otherwise, once per feature per process, it
/// logs a warning and writes a single non-critical audit row. It never throws — a failed audit write
/// is swallowed — so it can sit on a hot path without ever affecting the operation.
/// </summary>
public sealed class PremiumFeatureUsageRecorder : IPremiumFeatureUsage
{
    private readonly ILicenseState _license;
    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<PremiumFeatureUsageRecorder> _logger;
    private readonly ConcurrentDictionary<string, byte> _recorded = new(StringComparer.Ordinal);

    public PremiumFeatureUsageRecorder(
        ILicenseState license,
        IServiceScopeFactory scopes,
        ILogger<PremiumFeatureUsageRecorder> logger)
    {
        _license = license;
        _scopes = scopes;
        _logger = logger;
    }

    public async Task RecordUseAsync(string featureKey, CancellationToken ct)
    {
        // Licensed for this feature — nothing to surface. The common, hot-path branch.
        if (_license.Allows(featureKey))
            return;

        // Already surfaced this feature this process — one line is enough, never spam the trail.
        if (!_recorded.TryAdd(featureKey, 0))
            return;

        _logger.LogWarning(
            "Premium feature '{Feature}' was used without a license entitlement. This does not restrict " +
            "the vault — it is a licensing reminder.", featureKey);

        try
        {
            // The sink is scoped; take a scope of our own since this recorder is a singleton.
            await using var scope = _scopes.CreateAsyncScope();
            var sink = scope.ServiceProvider.GetRequiredService<IAuditSink>();
            await sink.WriteAsync(
                new AuditEntry
                {
                    Action = AuditAction.LicenseFeatureUnlicensed,
                    ResourceType = "License",
                    ResourceName = featureKey,
                    Details = $"Premium feature '{featureKey}' exercised without a license entitlement.",
                    IsCritical = false,
                    ActorUsername = "system"
                },
                ct);
        }
        catch (AuditWriteFailedException ex)
        {
            _logger.LogWarning(ex,
                "Could not record the unlicensed-feature-use audit row for '{Feature}' — continuing " +
                "(licensing never blocks the vault).", featureKey);
        }
    }
}
```

Note: `ILicenseState`, `IAuditSink`, `AuditEntry`, and `IPremiumFeatureUsage` resolve via the Infrastructure global usings (`Core.Application.Abstractions`); `AuditAction` and `AuditWriteFailedException` need the explicit `Domain.Enums` / `Domain.Exceptions` usings shown.

- [ ] **Step 5: Register in DI**

In `EclipsVault.Infrastructure/DependencyInjection.cs`, immediately after the existing licensing registration (`services.AddSingleton<ILicenseState, LicenseService>();`, ~line 173), add:

```csharp
        // Soft recorder for on-demand premium-feature use (dynamic secrets, managed rotation,
        // attestation). Singleton so its per-feature dedup is process-wide.
        services.AddSingleton<IPremiumFeatureUsage, PremiumFeatureUsageRecorder>();
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `dotnet test EclipsVault.slnx --filter "FullyQualifiedName~PremiumFeatureUsageRecorderTests"`
Expected: PASS (4 tests).

- [ ] **Step 7: Commit**

```bash
git add EclipsVault.Core/Application/Abstractions/IPremiumFeatureUsage.cs EclipsVault.Infrastructure/Security/Licensing/PremiumFeatureUsageRecorder.cs EclipsVault.Infrastructure/DependencyInjection.cs EclipsVault.Tests/Licensing/PremiumFeatureUsageRecorderTests.cs
git commit -m "feat: add soft premium-feature usage recorder"
```

---

### Task 3: `ConfiguredPremiumFeatures` detector

**Files:**
- Create: `EclipsVault.Infrastructure/Security/Licensing/ConfiguredPremiumFeatures.cs`
- Modify: `EclipsVault.Infrastructure/DependencyInjection.cs`
- Test: `EclipsVault.Tests/Licensing/ConfiguredPremiumFeaturesTests.cs`

**Interfaces:**
- Consumes: `CryptoOptions.Engine`, `RedisOptions.Enabled`, `SsoOptions.Authority`, `VaultTransitCryptoEngine.EngineName`, `LicenseFeatures.*` (existing).
- Produces: `ConfiguredPremiumFeatures.Active : IReadOnlySet<string>` — consumed by Task 4.

- [ ] **Step 1: Write the failing tests**

Create `EclipsVault.Tests/Licensing/ConfiguredPremiumFeaturesTests.cs`:

```csharp
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Infrastructure.Distributed;
using EclipsVault.Infrastructure.Security;
using EclipsVault.Infrastructure.Security.Cryptography;
using EclipsVault.Infrastructure.Security.Licensing;
using Microsoft.Extensions.Options;
using Xunit;

namespace EclipsVault.Tests.Licensing;

public class ConfiguredPremiumFeaturesTests
{
    private static ConfiguredPremiumFeatures Build(string engine, bool redis, string ssoAuthority)
        => new(
            Options.Create(new CryptoOptions { Engine = engine }),
            Options.Create(new RedisOptions { Enabled = redis }),
            Options.Create(new SsoOptions { Authority = ssoAuthority }));

    [Fact]
    public void Nothing_configured_is_empty()
        => Assert.Empty(Build(AesGcmCryptoEngine.EngineName, redis: false, ssoAuthority: "").Active);

    [Fact]
    public void VaultTransit_engine_activates_kms()
    {
        var active = Build(VaultTransitCryptoEngine.EngineName, redis: false, ssoAuthority: "").Active;
        Assert.Contains(LicenseFeatures.Kms, active);
        Assert.DoesNotContain(LicenseFeatures.RedisHa, active);
    }

    [Fact]
    public void Redis_enabled_activates_redis_ha()
        => Assert.Contains(LicenseFeatures.RedisHa, Build(AesGcmCryptoEngine.EngineName, redis: true, ssoAuthority: "").Active);

    [Fact]
    public void Sso_authority_activates_sso()
        => Assert.Contains(LicenseFeatures.Sso, Build(AesGcmCryptoEngine.EngineName, redis: false, ssoAuthority: "https://idp.example").Active);

    [Fact]
    public void All_three_configured_are_all_present()
    {
        var active = Build(VaultTransitCryptoEngine.EngineName, redis: true, ssoAuthority: "https://idp.example").Active;
        Assert.Equal(
            new HashSet<string> { LicenseFeatures.Kms, LicenseFeatures.RedisHa, LicenseFeatures.Sso },
            active);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test EclipsVault.slnx --filter "FullyQualifiedName~ConfiguredPremiumFeaturesTests"`
Expected: build/compile error — `ConfiguredPremiumFeatures` does not exist.

- [ ] **Step 3: Create the detector**

Create `EclipsVault.Infrastructure/Security/Licensing/ConfiguredPremiumFeatures.cs`:

```csharp
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Infrastructure.Distributed;
using EclipsVault.Infrastructure.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Security.Licensing;

/// <summary>
/// The premium (Max-only) features switched on by this deployment's configuration — the three chosen
/// at startup: the external KMS engine, Redis-backed HA, and SSO. Computed once from the bound options
/// so there is a single source of truth (the banner and the startup license check both read it), and
/// it can never drift from how each feature is actually selected.
/// </summary>
public sealed class ConfiguredPremiumFeatures
{
    public ConfiguredPremiumFeatures(
        IOptions<CryptoOptions> crypto,
        IOptions<RedisOptions> redis,
        IOptions<SsoOptions> sso)
    {
        var active = new HashSet<string>(StringComparer.Ordinal);

        if (string.Equals(crypto.Value.Engine, VaultTransitCryptoEngine.EngineName, StringComparison.Ordinal))
            active.Add(LicenseFeatures.Kms);

        if (redis.Value.Enabled)
            active.Add(LicenseFeatures.RedisHa);

        if (!string.IsNullOrWhiteSpace(sso.Value.Authority))
            active.Add(LicenseFeatures.Sso);

        Active = active;
    }

    /// <summary>The config-activated premium feature keys (<see cref="LicenseFeatures"/> constants).</summary>
    public IReadOnlySet<string> Active { get; }
}
```

Note: `CryptoOptions` and `SsoOptions` live in the parent namespace `EclipsVault.Infrastructure.Security`, which is visible from this child namespace without a `using`.

- [ ] **Step 4: Register in DI**

In `EclipsVault.Infrastructure/DependencyInjection.cs`, right after the recorder registration from Task 2, add:

```csharp
        // Single source of truth for config-activated premium features (banner + startup check read it).
        services.AddSingleton<ConfiguredPremiumFeatures>();
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `dotnet test EclipsVault.slnx --filter "FullyQualifiedName~ConfiguredPremiumFeaturesTests"`
Expected: PASS (5 tests).

- [ ] **Step 6: Commit**

```bash
git add EclipsVault.Infrastructure/Security/Licensing/ConfiguredPremiumFeatures.cs EclipsVault.Infrastructure/DependencyInjection.cs EclipsVault.Tests/Licensing/ConfiguredPremiumFeaturesTests.cs
git commit -m "feat: add ConfiguredPremiumFeatures detector"
```

---

### Task 4: Wire the detector into the banner + expand `LicenseStartupCheck`

**Files:**
- Modify: `EclipsVault.Web/Program.cs` (banner builder, ~lines 47-61)
- Modify: `EclipsVault.Infrastructure/Workers/LicenseStartupCheck.cs`
- Test: `EclipsVault.Tests/Licensing/LicenseStartupCheckTests.cs`

**Interfaces:**
- Consumes: `ConfiguredPremiumFeatures.Active` (Task 3); `AuditAction.LicenseFeatureUnlicensed` (Task 1).
- Produces: a `LicenseStartupCheck` ctor now taking `ConfiguredPremiumFeatures` (3rd param).

- [ ] **Step 1: Update the existing tests + add the new one**

Replace the body of `EclipsVault.Tests/Licensing/LicenseStartupCheckTests.cs` from the `SoftRowsAfterStartup` helper through the end of the class with the following (keep the `using`s at the top, and add `using EclipsVault.Core.Application.Licensing;`, `using EclipsVault.Infrastructure.Security;`, `using EclipsVault.Infrastructure.Distributed;`, `using EclipsVault.Infrastructure.Security.Licensing;`, `using Microsoft.Extensions.Options;`):

```csharp
    private static ConfiguredPremiumFeatures NoFeatures()
        => new(Options.Create(new CryptoOptions()), Options.Create(new RedisOptions()), Options.Create(new SsoOptions()));

    private static ConfiguredPremiumFeatures RedisActive()
        => new(Options.Create(new CryptoOptions()), Options.Create(new RedisOptions { Enabled = true }), Options.Create(new SsoOptions()));

    private static async Task<int> RowsAfterStartup(
        string environment,
        LicenseStatus status,
        ConfiguredPremiumFeatures features,
        AuditAction countAction)
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
                features,
                provider.GetRequiredService<IServiceScopeFactory>(),
                NullLogger<LicenseStartupCheck>.Instance);

            await check.StartAsync(CancellationToken.None);

            await using var read = provider.CreateAsyncScope();
            return await read.ServiceProvider.GetRequiredService<EclipsVaultDbContext>()
                .AuditLogs.CountAsync(a => a.Action == countAction && !a.IsCritical);
        }
        finally
        {
            await committer.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task Unlicensed_in_production_writes_one_soft_audit_row()
        => Assert.Equal(1, await RowsAfterStartup(
            Environments.Production, LicenseStatus.Missing, NoFeatures(), AuditAction.LicenseInvalidProductionUse));

    [Fact]
    public async Task Development_writes_no_row_even_when_unlicensed()
        => Assert.Equal(0, await RowsAfterStartup(
            Environments.Development, LicenseStatus.Missing, NoFeatures(), AuditAction.LicenseInvalidProductionUse));

    [Fact]
    public async Task A_valid_license_with_no_extra_features_writes_no_row()
        => Assert.Equal(0, await RowsAfterStartup(
            Environments.Production, LicenseStatus.Valid, NoFeatures(), AuditAction.LicenseInvalidProductionUse));

    [Fact]
    public async Task A_valid_license_using_a_feature_beyond_its_tier_writes_one_feature_row()
        => Assert.Equal(1, await RowsAfterStartup(
            Environments.Production, LicenseStatus.Valid, RedisActive(), AuditAction.LicenseFeatureUnlicensed));
```

(The `FakeLicense.Allows` returns `false`, so a valid license with `RedisActive()` is treated as Community-tier for `redis-ha` — exactly the beyond-tier case.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test EclipsVault.slnx --filter "FullyQualifiedName~LicenseStartupCheckTests"`
Expected: build/compile error — `LicenseStartupCheck` constructor does not take a `ConfiguredPremiumFeatures` argument.

- [ ] **Step 3: Expand `LicenseStartupCheck`**

In `EclipsVault.Infrastructure/Workers/LicenseStartupCheck.cs`: add the field + ctor param, and replace the `StartAsync` body. Add `using EclipsVault.Infrastructure.Security.Licensing;` at the top.

Add the field alongside the others and the ctor parameter (3rd position):

```csharp
    private readonly ILicenseState _license;
    private readonly IHostEnvironment _environment;
    private readonly ConfiguredPremiumFeatures _premiumFeatures;
    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<LicenseStartupCheck> _logger;

    public LicenseStartupCheck(
        ILicenseState license,
        IHostEnvironment environment,
        ConfiguredPremiumFeatures premiumFeatures,
        IServiceScopeFactory scopes,
        ILogger<LicenseStartupCheck> logger)
    {
        _license = license;
        _environment = environment;
        _premiumFeatures = premiumFeatures;
        _scopes = scopes;
        _logger = logger;
    }
```

Replace `StartAsync` (keep `StopAsync` as-is) with:

```csharp
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("License check: {Status} — {Message}", _license.Status, _license.Message);

        // Development runs unlicensed by design (no pinned key), so it is never nagged or recorded.
        if (_environment.IsDevelopment())
            return;

        if (_license.Status != LicenseStatus.Valid)
        {
            _logger.LogWarning(
                "EclipsVault is running without a valid license ({Status}). This does not restrict the vault — " +
                "it is a licensing reminder.", _license.Status);

            await WriteSoftRowAsync(
                AuditAction.LicenseInvalidProductionUse,
                _license.Status.ToString(),
                _license.Message,
                cancellationToken);
            return;
        }

        // A valid license can still be a lower tier than the features switched on (e.g. Community with
        // Redis HA). Surface exactly which config-active features it does not grant.
        var beyondTier = _premiumFeatures.Active.Where(feature => !_license.Allows(feature)).ToArray();
        if (beyondTier.Length == 0)
            return;

        var features = string.Join(", ", beyondTier);
        _logger.LogWarning(
            "EclipsVault has premium features active that the current license does not grant: {Features}. " +
            "This does not restrict the vault — it is a licensing reminder.", features);

        await WriteSoftRowAsync(
            AuditAction.LicenseFeatureUnlicensed,
            features,
            $"Config-active premium features beyond the current license: {features}.",
            cancellationToken);
    }

    private async Task WriteSoftRowAsync(AuditAction action, string resourceName, string details, CancellationToken ct)
    {
        try
        {
            // The sink is scoped; take a scope of our own since a hosted service is a singleton.
            await using var scope = _scopes.CreateAsyncScope();
            var sink = scope.ServiceProvider.GetRequiredService<IAuditSink>();
            await sink.WriteAsync(
                new AuditEntry
                {
                    Action = action,
                    ResourceType = "License",
                    ResourceName = resourceName,
                    Details = details,
                    // A licensing reminder must never masquerade as a genuine security incident.
                    IsCritical = false,
                    ActorUsername = "system"
                },
                ct);
        }
        catch (AuditWriteFailedException ex)
        {
            _logger.LogWarning(ex,
                "Could not record the licensing audit row — continuing (licensing never blocks the vault).");
        }
    }
```

- [ ] **Step 4: Update the banner builder in `Program.cs`**

In `EclipsVault.Web/Program.cs`, replace the "Precompute the licensing-banner inputs" block (the `builder.Services.AddSingleton(sp => { ... LicenseNudgeState.From(license, active); })`) with:

```csharp
    // Precompute the licensing-banner inputs once from the single config-active feature source. Soft —
    // it only decides what the banner says; it never changes what the vault does.
    builder.Services.AddSingleton(sp =>
    {
        var license = sp.GetRequiredService<ILicenseState>();
        var active = sp.GetRequiredService<ConfiguredPremiumFeatures>().Active;
        return LicenseNudgeState.From(license, active);
    });
```

Add `using EclipsVault.Infrastructure.Security.Licensing;` at the top of `Program.cs`. The old block was the only user of `LicenseFeatures` in `Program.cs`; if the compiler/editor flags `using EclipsVault.Core.Application.Licensing;` as now-unused, remove it (it is not needed for the build, but keep the file clean).

- [ ] **Step 5: Run tests to verify they pass**

Run: `dotnet test EclipsVault.slnx --filter "FullyQualifiedName~LicenseStartupCheckTests"`
Expected: PASS (4 tests).

- [ ] **Step 6: Build the whole solution (Program.cs has no unit test)**

Run: `dotnet build EclipsVault.slnx -c Debug`
Expected: `Build succeeded. 0 Warning(s) 0 Error(s)`.

- [ ] **Step 7: Commit**

```bash
git add EclipsVault.Infrastructure/Workers/LicenseStartupCheck.cs EclipsVault.Web/Program.cs EclipsVault.Tests/Licensing/LicenseStartupCheckTests.cs
git commit -m "feat: surface config-active premium features beyond license at startup"
```

---

### Task 5: Gate the dynamic-secrets call site

**Files:**
- Create: `EclipsVault.Tests/TestDoubles/RecordingPremiumFeatureUsage.cs`
- Modify: `EclipsVault.Core/Application/DynamicSecrets/DynamicSecretService.cs`
- Test: `EclipsVault.Tests/DynamicSecrets/DynamicSecretServiceTests.cs`

**Interfaces:**
- Consumes: `IPremiumFeatureUsage` (Task 2), `LicenseFeatures.DynamicSecrets`.
- Produces: `RecordingPremiumFeatureUsage` test double (used by Tasks 6, 7).

- [ ] **Step 1: Create the shared recording fake**

Create `EclipsVault.Tests/TestDoubles/RecordingPremiumFeatureUsage.cs`:

```csharp
using EclipsVault.Core.Application.Abstractions;

namespace EclipsVault.Tests.TestDoubles;

/// <summary>Records which feature keys were reported used; never changes behaviour.</summary>
public sealed class RecordingPremiumFeatureUsage : IPremiumFeatureUsage
{
    public List<string> Recorded { get; } = [];

    public Task RecordUseAsync(string featureKey, CancellationToken ct)
    {
        Recorded.Add(featureKey);
        return Task.CompletedTask;
    }
}
```

- [ ] **Step 2: Update the test `Build` helper + write the failing test**

In `EclipsVault.Tests/DynamicSecrets/DynamicSecretServiceTests.cs`, add `using EclipsVault.Core.Application.Abstractions;`, `using EclipsVault.Core.Application.Licensing;`, and `using EclipsVault.Tests.TestDoubles;` at the top. Replace the `Build` helper (line ~112) with:

```csharp
    private static DynamicSecretService Build(FakeRepository repository, FakeBackend backend, IPremiumFeatureUsage? usage = null)
        => new(repository, [backend], new StubActor(), TimeProvider.System, usage ?? new RecordingPremiumFeatureUsage());
```

Add this test to the class:

```csharp
    [Fact]
    public async Task Issuing_records_premium_usage_and_still_leases()
    {
        var role = Role();
        var repository = new FakeRepository(role);
        var backend = new FakeBackend();
        var usage = new RecordingPremiumFeatureUsage();

        var issued = await Build(repository, backend, usage).IssueAsync(role.Id, null, CancellationToken.None);

        Assert.Equal(LicenseFeatures.DynamicSecrets, Assert.Single(usage.Recorded));
        Assert.NotEmpty(issued.Secret); // behaviour unchanged: a lease was still issued
    }
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `dotnet test EclipsVault.slnx --filter "FullyQualifiedName~DynamicSecretServiceTests"`
Expected: build/compile error — `DynamicSecretService` constructor does not take a 5th argument.

- [ ] **Step 4: Add the ctor param + call site**

In `EclipsVault.Core/Application/DynamicSecrets/DynamicSecretService.cs`, add `using EclipsVault.Core.Application.Licensing;` at the top. Add a field and ctor parameter (append after `clock`):

```csharp
    private readonly IAuditContext _actor;
    private readonly TimeProvider _clock;
    private readonly IPremiumFeatureUsage _premiumUsage;

    public DynamicSecretService(
        IDynamicSecretRepository repository,
        IEnumerable<IDynamicSecretBackend> backends,
        IAuditContext actor,
        TimeProvider clock,
        IPremiumFeatureUsage premiumUsage)
    {
        _repository = repository;
        _backends = backends.ToDictionary(b => b.Backend);
        _actor = actor;
        _clock = clock;
        _premiumUsage = premiumUsage;
    }
```

In `IssueAsync`, after the `role.IsEnabled` guard and before `var backend = ResolveBackend(role);`, add:

```csharp
        if (!role.IsEnabled)
        {
            throw new VaultAdminException($"The role '{role.Name}' is disabled and cannot issue credentials.");
        }

        // Soft licensing signal — never blocks issuing.
        await _premiumUsage.RecordUseAsync(LicenseFeatures.DynamicSecrets, ct);

        var backend = ResolveBackend(role);
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `dotnet test EclipsVault.slnx --filter "FullyQualifiedName~DynamicSecretServiceTests"`
Expected: PASS (all existing tests + the new one).

- [ ] **Step 6: Commit**

```bash
git add EclipsVault.Tests/TestDoubles/RecordingPremiumFeatureUsage.cs EclipsVault.Core/Application/DynamicSecrets/DynamicSecretService.cs EclipsVault.Tests/DynamicSecrets/DynamicSecretServiceTests.cs
git commit -m "feat: record dynamic-secret issuance as premium usage"
```

---

### Task 6: Gate the managed-rotation call site

**Files:**
- Modify: `EclipsVault.Core/Application/Secrets/SecretService.cs`
- Test: `EclipsVault.Tests/Secrets/ManagedRotationTests.cs`

**Interfaces:**
- Consumes: `IPremiumFeatureUsage` (Task 2), `LicenseFeatures.ManagedRotation`, `RecordingPremiumFeatureUsage` (Task 5).

- [ ] **Step 1: Update the test `Build` helpers + write the failing test**

In `EclipsVault.Tests/Secrets/ManagedRotationTests.cs`, add `using EclipsVault.Core.Application.Licensing;` and `using EclipsVault.Tests.TestDoubles;` at the top. Replace the existing `Build` helper (line ~160) with these two overloads:

```csharp
    private static SecretService Build(FakeRepository repository, RecordingAuditSink audit, params IManagedSecretBackend[] backends)
        => Build(repository, audit, new RecordingPremiumFeatureUsage(), backends);

    private static SecretService Build(FakeRepository repository, RecordingAuditSink audit, RecordingPremiumFeatureUsage usage, params IManagedSecretBackend[] backends)
        => new(repository, new FakeCryptoEngine(), new NullCache(), new UnusedIntrusionResponse(),
               audit, new StubActor(), backends, TimeProvider.System, usage);
```

Add this test:

```csharp
    [Fact]
    public async Task Rotating_a_managed_secret_records_premium_usage()
    {
        var secret = ManagedSecret();
        var repository = new FakeRepository(secret);
        var usage = new RecordingPremiumFeatureUsage();

        await Build(repository, new RecordingAuditSink(), usage, new FakeBackend())
            .RotateManagedAsync(SecretId, null, CancellationToken.None);

        Assert.Equal(LicenseFeatures.ManagedRotation, Assert.Single(usage.Recorded));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test EclipsVault.slnx --filter "FullyQualifiedName~ManagedRotationTests"`
Expected: build/compile error — `SecretService` constructor does not take a 9th argument.

- [ ] **Step 3: Add the ctor param + call site**

In `EclipsVault.Core/Application/Secrets/SecretService.cs`, add `using EclipsVault.Core.Application.Licensing;` at the top. Add a field and ctor parameter (append after `clock`):

```csharp
        IEnumerable<IManagedSecretBackend> managedBackends,
        TimeProvider clock,
        IPremiumFeatureUsage premiumUsage)
    {
        _repository = repository;
        _cryptoFactory = cryptoFactory;
        _cache = cache;
        _intrusion = intrusion;
        _audit = audit;
        _actor = actor;
        _managedBackends = [.. managedBackends];
        _clock = clock;
        _premiumUsage = premiumUsage;
    }
```

Declare the field next to the others:

```csharp
    private readonly IPremiumFeatureUsage _premiumUsage;
```

In `RotateManagedAsync`, after the `if (!entity.IsManaged)` guard block (which throws) and before the backend resolution (`var backend = _managedBackends.FirstOrDefault(...)`), add:

```csharp
        // Soft licensing signal — never blocks rotation.
        await _premiumUsage.RecordUseAsync(LicenseFeatures.ManagedRotation, ct);

        var backend = _managedBackends.FirstOrDefault(b => b.Backend == entity.RotationBackend)
            ?? throw new VaultAdminException($"No backend is configured for '{entity.RotationBackend}'.");
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test EclipsVault.slnx --filter "FullyQualifiedName~ManagedRotationTests"`
Expected: PASS (all existing tests + the new one).

- [ ] **Step 5: Commit**

```bash
git add EclipsVault.Core/Application/Secrets/SecretService.cs EclipsVault.Tests/Secrets/ManagedRotationTests.cs
git commit -m "feat: record managed rotation as premium usage"
```

---

### Task 7: Gate the audit-attestation call site

**Files:**
- Modify: `EclipsVault.Infrastructure/Auditing/AuditCheckpointService.cs`
- Test: `EclipsVault.Tests/Auditing/AuditCheckpointServiceTests.cs`

**Interfaces:**
- Consumes: `IPremiumFeatureUsage` (Task 2), `LicenseFeatures.AuditAttestation`, `RecordingPremiumFeatureUsage` (Task 5), `IAuditCheckpointSigner`, `IAuditSink`.

Placement note: attestation has no input to validate, and an empty audit chain is a no-op short-circuit (`return null`), not invalid input. So the recorder call goes at the **top** of `CreateCheckpointAsync` — invoking the attestation feature is the premium use. Dedup makes an empty-chain call harmless.

- [ ] **Step 1: Write the failing test**

Create `EclipsVault.Tests/Auditing/AuditCheckpointServiceTests.cs`:

```csharp
using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Infrastructure.Auditing;
using EclipsVault.Infrastructure.Persistence;
using EclipsVault.Tests.TestDoubles;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace EclipsVault.Tests.Auditing;

public class AuditCheckpointServiceTests
{
    private sealed class FakeSigner : IAuditCheckpointSigner
    {
        public byte[] Sign(byte[] canonical) => [];
        public byte[] PublicKeySpki => [];
        public string KeyId => "test-key";
    }

    private sealed class NoOpAuditSink : IAuditSink
    {
        public Task WriteAsync(AuditEntry entry, CancellationToken ct) => Task.CompletedTask;
    }

    [Fact]
    public async Task Creating_a_checkpoint_records_premium_usage()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();

        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddDbContext<EclipsVaultDbContext>(o => o.UseSqlite(connection));
        await using var provider = services.BuildServiceProvider();

        await using var scope = provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<EclipsVaultDbContext>();
        await db.Database.EnsureCreatedAsync();

        var usage = new RecordingPremiumFeatureUsage();
        var service = new AuditCheckpointService(db, new FakeSigner(), new NoOpAuditSink(), TimeProvider.System, usage);

        var result = await service.CreateCheckpointAsync(CancellationToken.None);

        Assert.Null(result); // empty chain → nothing to sign
        Assert.Equal(LicenseFeatures.AuditAttestation, Assert.Single(usage.Recorded));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test EclipsVault.slnx --filter "FullyQualifiedName~AuditCheckpointServiceTests"`
Expected: build/compile error — `AuditCheckpointService` constructor does not take a 5th argument.

- [ ] **Step 3: Add the ctor param + call site**

In `EclipsVault.Infrastructure/Auditing/AuditCheckpointService.cs`, add `using EclipsVault.Core.Application.Licensing;` at the top. Add a field and ctor parameter (append after `clock`):

```csharp
    private readonly IAuditSink _audit;
    private readonly TimeProvider _clock;
    private readonly IPremiumFeatureUsage _premiumUsage;

    public AuditCheckpointService(EclipsVaultDbContext db, IAuditCheckpointSigner signer, IAuditSink audit, TimeProvider clock, IPremiumFeatureUsage premiumUsage)
    {
        _db = db;
        _signer = signer;
        _audit = audit;
        _clock = clock;
        _premiumUsage = premiumUsage;
    }
```

Make `CreateCheckpointAsync` record usage as its first statement:

```csharp
    public async Task<AuditCheckpointDto?> CreateCheckpointAsync(CancellationToken ct)
    {
        // Soft licensing signal — never blocks checkpointing.
        await _premiumUsage.RecordUseAsync(LicenseFeatures.AuditAttestation, ct);

        var head = await HeadAsync(ct);
        if (head is null)
        {
            return null; // nothing chained yet
        }
        // ... rest unchanged ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test EclipsVault.slnx --filter "FullyQualifiedName~AuditCheckpointServiceTests"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add EclipsVault.Infrastructure/Auditing/AuditCheckpointService.cs EclipsVault.Tests/Auditing/AuditCheckpointServiceTests.cs
git commit -m "feat: record audit-checkpoint creation as premium usage"
```

---

### Task 8: Full regression + verification

**Files:** none (verification only).

- [ ] **Step 1: Full clean build**

Run: `dotnet build EclipsVault.slnx -c Debug`
Expected: `Build succeeded. 0 Warning(s) 0 Error(s)`.

- [ ] **Step 2: Full test suite**

Run: `dotnet test EclipsVault.slnx -c Debug`
Expected: `Passed! Failed: 0` — the prior 434 plus the new tests (≈448), 0 failed, 0 skipped.

- [ ] **Step 3: Confirm the DI graph resolves at runtime**

The three gated services now take `IPremiumFeatureUsage`, and `LicenseStartupCheck` takes `ConfiguredPremiumFeatures`; both are registered (Tasks 2, 3). The passing test suite plus a clean build confirm the graph. If a runtime smoke test is desired, launch the app per the project run instructions and confirm it starts and logs a license line.

- [ ] **Step 4: (Optional) open the PR**

```bash
git push -u origin feat/license-feature-gating
gh pr create --title "Soft license feature gating (Phase 1)" --body "Implements docs/superpowers/specs/2026-07-20-license-feature-gating-design.md. Surfaces all six Max-only features when run unlicensed/beyond-tier via a single ConfiguredPremiumFeatures source (startup) and a soft, deduplicated IPremiumFeatureUsage recorder (call sites). No feature disabled, no new UI, secret path untouched. Build 0/0; full suite green."
```

---

## Notes for the implementer

- **Order matters:** Task 1 → 2 → 3 → 4 → (5, 6, 7 independent) → 8. Tasks 5-7 all depend on Task 2's `IPremiumFeatureUsage` and Task 5's `RecordingPremiumFeatureUsage`.
- **Never** add a runtime check that changes behavior — every recorder/detector path must leave the operation's result identical.
- If any `dotnet build` reports a warning (warnings are errors here), fix it before committing — do not suppress.
- `LicenseFeatures` is **not** a global using; add `using EclipsVault.Core.Application.Licensing;` wherever you reference it (Tasks 3, 4, 5, 6, 7 and their tests).
