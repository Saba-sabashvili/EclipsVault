# Premium-Feature Activation Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refuse the two lockout-proof premium features (dynamic-secret issuance, managed rotation) when the resolved licence does not grant them, instead of merely noting the use.

**Architecture:** Promote the existing `IPremiumFeatureUsage` seam. Add `RequireAsync(feature)` that, when the feature is in a single `LicenseFeatures.Gated` set and unlicensed, writes a `LicenseFeatureBlocked` audit row and throws `PremiumFeatureNotLicensedException`; non-gated features keep today's soft `RecordUseAsync` behaviour. The two Core call sites switch to `RequireAsync`; the Web layer maps the exception to a 402 and a friendly flash.

**Tech Stack:** .NET 10, ASP.NET Core MVC, EF Core, xUnit. Clean Architecture (Core → Infrastructure → Web).

**Spec:** `docs/superpowers/specs/2026-09-06-premium-feature-activation-gate-design.md`

## Global Constraints

- **Fail-open, never lock out:** only *issuing new* leases and *re-rotating* are gated. Existing leases keep working and stay revocable; a managed secret keeps its current value; the secret read/decrypt path is never touched.
- **A licensing check must never crash the vault:** the audit write on refusal is best-effort and swallowed (exactly as the current recorder does); the only thing that propagates is `PremiumFeatureNotLicensedException`, which the Web layer turns into a 402 — never a 500.
- **Refusal status is 402 Payment Required** (surfaced via the existing `/Home/Error?code=NNN` pattern for uncaught cases; a friendly flash + redirect on the interactive UI paths).
- **Only these two features are gated this cut.** SSO, KMS, Redis HA, audit attestation stay soft.
- **Core has zero external package references** — enforced by `LayeringTests`. New Core files use only the BCL + existing Core types.
- **Follow existing patterns:** exceptions derive from `DomainException`; controllers catch specific domain exceptions and `FlashError` + redirect.

---

### Task 1: The enforcement primitive (`RequireAsync`)

**Files:**
- Modify: `EclipsVault.Core/Application/Licensing/LicenseFeatures.cs` (add `Gated`)
- Modify: `EclipsVault.Core/Application/Abstractions/IPremiumFeatureUsage.cs` (add `RequireAsync`)
- Create: `EclipsVault.Core/Domain/Exceptions/PremiumFeatureNotLicensedException.cs`
- Modify: `EclipsVault.Core/Domain/Enums/AuditAction.cs` (add `LicenseFeatureBlocked = 202`)
- Modify: `EclipsVault.Infrastructure/Security/Licensing/PremiumFeatureUsageRecorder.cs` (implement `RequireAsync`, extract shared writer)
- Test: `EclipsVault.Tests/Licensing/PremiumFeatureUsageRecorderTests.cs` (extend)

**Interfaces:**
- Produces: `IPremiumFeatureUsage.RequireAsync(string featureKey, CancellationToken ct) : Task`; `LicenseFeatures.Gated : IReadOnlySet<string>`; `PremiumFeatureNotLicensedException(string featureKey)` with `string FeatureKey { get; }`; `AuditAction.LicenseFeatureBlocked`.
- Consumes: existing `ILicenseState.Allows`, `IAuditSink`, `IServiceScopeFactory`.

- [ ] **Step 1: Add the gated set to `LicenseFeatures`**

In `EclipsVault.Core/Application/Licensing/LicenseFeatures.cs`, inside `public static class LicenseFeatures`, after the string constants:

```csharp
    /// <summary>
    /// The features that are hard-gated: an unlicensed vault refuses the action rather than merely
    /// noting it. Everything else stays soft. This is the single source of truth for which features
    /// enforce — adding one here (plus, for SSO, a no-lockout safeguard) is the whole change.
    /// Both gated features degrade gracefully: only issuing a new lease / re-rotating is refused, so
    /// nothing at rest is ever locked.
    /// </summary>
    public static readonly IReadOnlySet<string> Gated =
        new HashSet<string>(StringComparer.Ordinal) { DynamicSecrets, ManagedRotation };
```

- [ ] **Step 2: Add `LicenseFeatureBlocked` to the audit actions**

In `EclipsVault.Core/Domain/Enums/AuditAction.cs`, change the last licence line to add the new member (keep the trailing values contiguous):

```csharp
    LicenseInvalidProductionUse = 200,
    LicenseFeatureUnlicensed = 201,
    LicenseFeatureBlocked = 202
```

- [ ] **Step 3: Create the exception**

Create `EclipsVault.Core/Domain/Exceptions/PremiumFeatureNotLicensedException.cs`:

```csharp
namespace EclipsVault.Core.Domain.Exceptions;

/// <summary>
/// Raised when a gated premium feature is used without a licence that grants it. It is a payment /
/// entitlement boundary, not a fault: the operation is refused cleanly and nothing at rest is touched.
/// The Web layer maps it to 402 Payment Required.
/// </summary>
public sealed class PremiumFeatureNotLicensedException : DomainException
{
    public PremiumFeatureNotLicensedException(string featureKey)
        : base($"The '{featureKey}' feature requires a licence.")
        => FeatureKey = featureKey;

    /// <summary>The <c>LicenseFeatures</c> key that was refused.</summary>
    public string FeatureKey { get; }
}
```

- [ ] **Step 4: Add `RequireAsync` to the interface**

In `EclipsVault.Core/Application/Abstractions/IPremiumFeatureUsage.cs`, add to the interface (below `RecordUseAsync`):

```csharp
    /// <summary>
    /// Require a licence for <paramref name="featureKey"/> before the caller proceeds. Licensed: a
    /// no-op. Unlicensed and <see cref="Licensing.LicenseFeatures.Gated">gated</see>: records one
    /// deduplicated <c>LicenseFeatureBlocked</c> audit line and throws
    /// <see cref="Domain.Exceptions.PremiumFeatureNotLicensedException"/> on every call. Unlicensed and
    /// not gated: behaves exactly like <see cref="RecordUseAsync"/> (soft, never throws).
    /// </summary>
    Task RequireAsync(string featureKey, CancellationToken ct);
```

Add the using if needed: `using EclipsVault.Core.Application.Licensing;` is not required for a doc-comment cref, so no new using.

- [ ] **Step 5: Update the shared test double so the Tests project still compiles**

Adding `RequireAsync` to the interface forces every implementer to define it. The only test implementer is the shared `EclipsVault.Tests/TestDoubles/RecordingPremiumFeatureUsage.cs`. Update it to **default-allow** (so the many existing issue/rotate tests keep passing) with an opt-in `Denied` set for the refusal tests. Add `using EclipsVault.Core.Domain.Exceptions;` and replace the class body:

```csharp
public sealed class RecordingPremiumFeatureUsage : IPremiumFeatureUsage
{
    public List<string> Recorded { get; } = [];

    /// <summary>Features to refuse from <see cref="RequireAsync"/>. Empty by default — everything is allowed.</summary>
    public HashSet<string> Denied { get; } = new(StringComparer.Ordinal);

    public Task RecordUseAsync(string featureKey, CancellationToken ct)
    {
        Recorded.Add(featureKey);
        return Task.CompletedTask;
    }

    public Task RequireAsync(string featureKey, CancellationToken ct)
    {
        Recorded.Add(featureKey);
        return Denied.Contains(featureKey)
            ? throw new PremiumFeatureNotLicensedException(featureKey)
            : Task.CompletedTask;
    }
}
```

- [ ] **Step 6: Write the failing tests**

Append to `EclipsVault.Tests/Licensing/PremiumFeatureUsageRecorderTests.cs` (reuses the existing `FakeLicense`, `NoOpAuditSink` added here, and the `RowsAfter` harness):

```csharp
    private sealed class NoOpAuditSink : IAuditSink
    {
        public Task WriteAsync(AuditEntry entry, CancellationToken ct) => Task.CompletedTask;
    }

    private static PremiumFeatureUsageRecorder RecorderWith(ILicenseState license)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddScoped<IAuditSink, NoOpAuditSink>();
        var provider = services.BuildServiceProvider();
        return new PremiumFeatureUsageRecorder(
            license, provider.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<PremiumFeatureUsageRecorder>.Instance);
    }

    [Fact]
    public async Task Require_throws_for_a_gated_feature_when_unlicensed()
    {
        var recorder = RecorderWith(new FakeLicense()); // grants nothing
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
        var recorder = RecorderWith(new FakeLicense());
        await Assert.ThrowsAsync<PremiumFeatureNotLicensedException>(
            () => recorder.RequireAsync(LicenseFeatures.DynamicSecrets, CancellationToken.None));
        await Assert.ThrowsAsync<PremiumFeatureNotLicensedException>(
            () => recorder.RequireAsync(LicenseFeatures.DynamicSecrets, CancellationToken.None));
    }
```

- [ ] **Step 7: Run the tests to verify they fail**

Run: `dotnet test EclipsVault.Tests/EclipsVault.Tests.csproj --filter "FullyQualifiedName~PremiumFeatureUsageRecorderTests"`
Expected: FAIL — compile error, `PremiumFeatureUsageRecorder` does not implement `RequireAsync`.

- [ ] **Step 8: Implement `RequireAsync` and extract the shared writer**

In `EclipsVault.Infrastructure/Security/Licensing/PremiumFeatureUsageRecorder.cs`, add `using EclipsVault.Core.Domain.Exceptions;` and `using EclipsVault.Core.Application.Licensing;` if not present, then refactor. Replace the body of `RecordUseAsync` and add `RequireAsync`, both delegating to a shared writer:

```csharp
    public async Task RecordUseAsync(string featureKey, CancellationToken ct)
    {
        if (_license.Allows(featureKey))
            return;

        await RecordUnlicensedAsync(featureKey, AuditAction.LicenseFeatureUnlicensed, blocked: false, ct);
    }

    public async Task RequireAsync(string featureKey, CancellationToken ct)
    {
        if (_license.Allows(featureKey))
            return;

        var gated = LicenseFeatures.Gated.Contains(featureKey);
        await RecordUnlicensedAsync(
            featureKey,
            gated ? AuditAction.LicenseFeatureBlocked : AuditAction.LicenseFeatureUnlicensed,
            blocked: gated,
            ct);

        // The audit row is deduped, but the refusal is not: every call is refused.
        if (gated)
            throw new PremiumFeatureNotLicensedException(featureKey);
    }

    private async Task RecordUnlicensedAsync(string featureKey, AuditAction action, bool blocked, CancellationToken ct)
    {
        // Already surfaced this feature this process — one line is enough, never spam the trail.
        if (!_recorded.TryAdd(featureKey, 0))
            return;

        _logger.LogWarning(
            blocked
                ? "Premium feature '{Feature}' was refused: no license entitlement. Existing state is unaffected."
                : "Premium feature '{Feature}' was used without a license entitlement. This does not restrict the vault — it is a licensing reminder.",
            featureKey);

        try
        {
            await using var scope = _scopes.CreateAsyncScope();
            var sink = scope.ServiceProvider.GetRequiredService<IAuditSink>();
            await sink.WriteAsync(
                new AuditEntry
                {
                    Action = action,
                    ResourceType = "License",
                    ResourceName = featureKey,
                    Details = blocked
                        ? $"Premium feature '{featureKey}' refused — not licensed."
                        : $"Premium feature '{featureKey}' exercised without a license entitlement.",
                    IsCritical = false,
                    ActorUsername = "system"
                },
                ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Could not record the premium-feature audit row for '{Feature}' — continuing " +
                "(licensing never blocks the vault).", featureKey);
        }
    }
```

Note: this widens the per-process dedup to cover both actions via one `_recorded` map — correct, because a feature is either gated (Blocked only) or not (Unlicensed only), never both.

- [ ] **Step 9: Run the tests to verify they pass**

Run: `dotnet test EclipsVault.Tests/EclipsVault.Tests.csproj --filter "FullyQualifiedName~PremiumFeatureUsageRecorderTests"`
Expected: PASS (existing soft-behaviour tests + the four new ones).

- [ ] **Step 10: Commit**

```bash
git add EclipsVault.Core EclipsVault.Infrastructure/Security/Licensing/PremiumFeatureUsageRecorder.cs EclipsVault.Tests/Licensing/PremiumFeatureUsageRecorderTests.cs
git commit -m "Add RequireAsync: refuse gated premium features when unlicensed

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Gate dynamic-secret issuance

**Files:**
- Modify: `EclipsVault.Core/Application/DynamicSecrets/DynamicSecretService.cs:55`
- Test: `EclipsVault.Tests/DynamicSecrets/DynamicSecretServiceTests.cs` (extend)

**Interfaces:**
- Consumes: `IPremiumFeatureUsage.RequireAsync` (Task 1), `PremiumFeatureNotLicensedException` (Task 1).

- [ ] **Step 1: Write the failing tests**

The shared `RecordingPremiumFeatureUsage` already has `RequireAsync` + `Denied` from Task 1. Use the existing `Build(FakeRepository, FakeBackend, IPremiumFeatureUsage?)` helper, `Role()`, `Owner`, and `FakeBackend.Minted`. Add to `EclipsVault.Tests/DynamicSecrets/DynamicSecretServiceTests.cs` (add `using EclipsVault.Core.Domain.Exceptions;` and `using EclipsVault.Core.Application.Licensing;` if not present):

```csharp
    [Fact]
    public async Task Issue_is_refused_when_dynamic_secrets_are_not_licensed()
    {
        var role = Role();
        var backend = new FakeBackend();
        var usage = new RecordingPremiumFeatureUsage();
        usage.Denied.Add(LicenseFeatures.DynamicSecrets);

        await Assert.ThrowsAsync<PremiumFeatureNotLicensedException>(
            () => Build(new FakeRepository(role), backend, usage).IssueAsync(role.Id, null, CancellationToken.None));

        Assert.Empty(backend.Minted); // refused before the backend was touched — nothing leased
    }

    [Fact]
    public async Task Revoke_still_succeeds_when_dynamic_secrets_are_no_longer_licensed()
    {
        // No-lockout invariant: an existing lease stays revocable after the licence lapses — only
        // *issuing* is gated. RevokeAsync has no gate; this pins that it stays that way.
        var role = Role();
        var backend = new FakeBackend();
        var usage = new RecordingPremiumFeatureUsage();
        var service = Build(new FakeRepository(role), backend, usage);
        var issued = await service.IssueAsync(role.Id, null, CancellationToken.None); // allowed

        usage.Denied.Add(LicenseFeatures.DynamicSecrets); // licence lapses

        Assert.True(await service.RevokeAsync(issued.LeaseId, Owner, isAdmin: false, CancellationToken.None));
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `dotnet test EclipsVault.Tests/EclipsVault.Tests.csproj --filter "FullyQualifiedName~DynamicSecretServiceTests"`
Expected: FAIL — `IssueAsync` still calls `RecordUseAsync` (soft) and issues.

- [ ] **Step 3: Switch the call site to `RequireAsync`**

In `EclipsVault.Core/Application/DynamicSecrets/DynamicSecretService.cs`, replace lines 54-55:

```csharp
        // Gate: a trial or paid licence is required to issue a dynamic credential. Refused before any
        // credential is minted, so nothing is leased and there is nothing to undo. Existing leases and
        // their revocation are unaffected.
        await _premiumUsage.RequireAsync(LicenseFeatures.DynamicSecrets, ct);
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `dotnet test EclipsVault.Tests/EclipsVault.Tests.csproj --filter "FullyQualifiedName~DynamicSecretServiceTests"`
Expected: PASS (the new refusal test, plus the existing licensed-issue test once its fake marks `DynamicSecrets` licensed).

- [ ] **Step 5: Commit**

```bash
git add EclipsVault.Core/Application/DynamicSecrets/DynamicSecretService.cs EclipsVault.Tests/DynamicSecrets/DynamicSecretServiceTests.cs
git commit -m "Gate dynamic-secret issuance behind a licence

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Gate managed rotation

**Files:**
- Modify: `EclipsVault.Core/Application/Secrets/SecretService.cs:177`
- Test: `EclipsVault.Tests/Secrets/ManagedRotationTests.cs` (extend)

**Interfaces:**
- Consumes: `IPremiumFeatureUsage.RequireAsync`, `PremiumFeatureNotLicensedException` (Task 1).

- [ ] **Step 1: Write the failing test**

Use the existing `Build(FakeRepository, RecordingAuditSink, RecordingPremiumFeatureUsage, params IManagedSecretBackend[])` overload, `ManagedSecret()`, `SecretId`, and `FakeBackend.Rotations`. Add to `EclipsVault.Tests/Secrets/ManagedRotationTests.cs` (add `using EclipsVault.Core.Domain.Exceptions;` and `using EclipsVault.Core.Application.Licensing;` if not present):

```csharp
    [Fact]
    public async Task Managed_rotation_is_refused_when_not_licensed()
    {
        var backend = new FakeBackend();
        var usage = new RecordingPremiumFeatureUsage();
        usage.Denied.Add(LicenseFeatures.ManagedRotation);

        await Assert.ThrowsAsync<PremiumFeatureNotLicensedException>(
            () => Build(new FakeRepository(ManagedSecret()), new RecordingAuditSink(), usage, backend)
                .RotateManagedAsync(SecretId, null, CancellationToken.None));

        Assert.Empty(backend.Rotations); // backend untouched; the stored value stays the truth
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `dotnet test EclipsVault.Tests/EclipsVault.Tests.csproj --filter "FullyQualifiedName~ManagedRotationTests"`
Expected: FAIL — rotation still proceeds (soft `RecordUseAsync`).

- [ ] **Step 3: Switch the call site to `RequireAsync`**

In `EclipsVault.Core/Application/Secrets/SecretService.cs`, replace lines 176-177:

```csharp
        // Gate: a trial or paid licence is required to have the vault change the real credential.
        // Refused before the backend is touched, so the stored value stays the truth. (The secret and
        // its read/decrypt path are never affected — only re-rotation is gated.)
        await _premiumUsage.RequireAsync(LicenseFeatures.ManagedRotation, ct);
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `dotnet test EclipsVault.Tests/EclipsVault.Tests.csproj --filter "FullyQualifiedName~ManagedRotationTests"`
Expected: PASS (the existing rotation tests must mark `ManagedRotation` licensed in their usage double).

- [ ] **Step 5: Commit**

```bash
git add EclipsVault.Core/Application/Secrets/SecretService.cs EclipsVault.Tests/Secrets/ManagedRotationTests.cs
git commit -m "Gate managed rotation behind a licence

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Web surfacing — 402 mapping + friendly flash

**Files:**
- Modify: `EclipsVault.Web/Middleware/GlobalExceptionMiddleware.cs` (add a catch before `DomainException`)
- Modify: `EclipsVault.Web/Controllers/DynamicSecretsController.cs` (Issue action, ~line 76)
- Modify: `EclipsVault.Web/Controllers/SecretsController.cs` (RotateManaged action, ~line 228)
- Verify: `EclipsVault.Web/Controllers/HomeController.cs` / `Views/Home/Error.cshtml` render `code=402`

**Interfaces:**
- Consumes: `PremiumFeatureNotLicensedException` (Task 1).

- [ ] **Step 1: Map the exception to 402 in the middleware**

In `EclipsVault.Web/Middleware/GlobalExceptionMiddleware.cs`, add this catch **before** the `catch (DomainException ex)` block (order matters — the specific type must win):

```csharp
        catch (PremiumFeatureNotLicensedException ex) when (!context.Response.HasStarted)
        {
            // A payment/entitlement boundary, not a fault: 402, not 400/500. Existing state is intact.
            _logger.LogInformation("Refused unlicensed premium feature '{Feature}' during {Path}", ex.FeatureKey, context.Request.Path);
            context.Response.Redirect("/Home/Error?code=402");
        }
```

- [ ] **Step 2: Confirm the error page renders 402**

Open `EclipsVault.Web/Controllers/HomeController.cs` (the `Error` action) / `Views/Home/Error.cshtml`. If it maps codes to messages, add a 402 entry: *"This feature requires a licence. Start a free 30-day trial, or install your licence."* If it renders an unknown code generically, that default is acceptable — but prefer the specific message. Make the minimal edit that gives 402 a clear message.

- [ ] **Step 3: Friendly flash on the dynamic-secrets Issue action**

In `EclipsVault.Web/Controllers/DynamicSecretsController.cs`, add a catch **before** `catch (VaultAdminException ex)` (~line 76):

```csharp
        catch (PremiumFeatureNotLicensedException)
        {
            this.FlashError("Dynamic secrets require a licence. Start a free 30-day trial, or install your licence.");
            return RedirectToAction(nameof(Index));
        }
```

Add `using EclipsVault.Core.Domain.Exceptions;` if not already present.

- [ ] **Step 4: Friendly flash on the RotateManaged action**

In `EclipsVault.Web/Controllers/SecretsController.cs`, add a catch **before** `catch (VaultAdminException ex)` (~line 228):

```csharp
        catch (PremiumFeatureNotLicensedException)
        {
            this.FlashError("Managed rotation requires a licence. Start a free 30-day trial, or install your licence.");
            return RedirectToAction(nameof(Details), new { id });
        }
```

Add the using if needed.

- [ ] **Step 5: Build and run the full suite**

Run: `dotnet test EclipsVault.slnx -c Release`
Expected: PASS (no regressions; these are additive catches).

- [ ] **Step 6: Commit**

```bash
git add EclipsVault.Web/Middleware/GlobalExceptionMiddleware.cs EclipsVault.Web/Controllers/DynamicSecretsController.cs EclipsVault.Web/Controllers/SecretsController.cs EclipsVault.Web/Controllers/HomeController.cs EclipsVault.Web/Views/Home/Error.cshtml
git commit -m "Surface an unlicensed premium refusal as a 402 with a clear message

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Proactive UI nudge + audit-log display

**Files:**
- Modify: `EclipsVault.Web/Controllers/DynamicSecretsController.cs` + `Views/DynamicSecrets/Index.cshtml` (nudge)
- Modify: the managed-rotation control in `Views/Secrets/Details.cshtml` (nudge)
- Modify: `EclipsVault.Core/Application/Activity/ActivityDescriber.cs` (describe `LicenseFeatureBlocked`)
- Modify: `EclipsVault.Web/Models/AuditViewModels.cs` (label `LicenseFeatureBlocked`)
- Test: `EclipsVault.Tests` — extend the existing `ActivityDescriber` test set if present

**Interfaces:**
- Consumes: `ILicenseState.Allows` (existing), `AuditAction.LicenseFeatureBlocked` (Task 1).

- [ ] **Step 1: Describe the new audit action (activity feed)**

In `EclipsVault.Core/Application/Activity/ActivityDescriber.cs`, next to the existing `AuditAction.AuditBundleExported => ...` / licence cases, add:

```csharp
        AuditAction.LicenseFeatureBlocked => new(ActivityCategory.Administration, "Refused an unlicensed premium feature", ActivitySeverity.Notable),
```

- [ ] **Step 2: Label the new action (audit viewer)**

In `EclipsVault.Web/Models/AuditViewModels.cs`, next to the existing `AuditAction.AuditBundleExported => ("Audit exported", "muted")` mapping, add:

```csharp
        AuditAction.LicenseFeatureBlocked => ("Feature blocked (unlicensed)", "muted"),
```

- [ ] **Step 3: Nudge on the dynamic-secrets page**

Inject `ILicenseState` into `DynamicSecretsController` (constructor) and pass `license.Allows(LicenseFeatures.DynamicSecrets)` into the view model (add a `bool DynamicSecretsLicensed` to `DynamicSecretsViewModel`). In `Views/DynamicSecrets/Index.cshtml`, when it is false, render an inline notice above the issue controls: *"Dynamic secrets require a licence — start a free 30-day trial."* Do not disable listing/revocation (existing leases must stay manageable).

- [ ] **Step 4: Nudge on the managed-rotation control**

Where `Views/Secrets/Details.cshtml` renders the "Rotate managed" button (only shown for `IsManaged` secrets), when `!license.Allows(LicenseFeatures.ManagedRotation)` render the same notice beside it. Surface the flag via the details view model (add `bool ManagedRotationLicensed`, set in `SecretsController`).

- [ ] **Step 5: Build and run the full suite**

Run: `dotnet test EclipsVault.slnx -c Release`
Expected: PASS.

- [ ] **Step 6: Manual check (optional but recommended)**

Run the app **without** `ECLIPSVAULT_LICENSE` (unlicensed): the two pages show the nudge, issuing a dynamic credential and rotating a managed secret each show the licence flash, and the Audit log shows a `Feature blocked (unlicensed)` row. Then set a trial token (`mint --trial-days 30`) and confirm both actions succeed and the nudge is gone.

- [ ] **Step 7: Commit**

```bash
git add EclipsVault.Core/Application/Activity/ActivityDescriber.cs EclipsVault.Web
git commit -m "Show a licence nudge on gated features and label blocked audit rows

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Notes for the executor

- **Existing tests will break at Tasks 2–3 until their `IPremiumFeatureUsage` fakes implement `RequireAsync`** and mark the relevant feature licensed for the happy-path tests. That is expected — update the fakes as part of each task.
- **Do not** add a background scheduler for rotation; managed rotation is user-initiated only. If one is ever added, its gate must *skip-and-log*, not throw (see spec, Out of scope #3).
- After all tasks: run `dotnet test EclipsVault.slnx -c Release` once more; the full suite must be green before this work is considered done.
