# License Feature Gating (Soft Surfacing) — Design

*Status: approved for planning. Owner: Saba Sabashvili. Date: 2026-07-20.*
*Roadmap: Phase 1 "call-site gating" (the update-window / tier split already landed on `main` at `82d4777`).*
*Companion decisions live in `docs/GTM_STRATEGY.md` (§1 features, §2 soft enforcement).*

---

## 1. Problem

Only **3 of the 6** Max-only features are visible to licensing today:

- `Program.cs` (~lines 47–61) inline-detects **KMS / Redis HA / SSO** from raw config strings
  (`"Crypto:Engine"=="VaultTransit"`, `"Redis:Enabled"`, `"Sso:Authority"`) and feeds
  `LicenseNudgeState` (the banner).
- **Dynamic secrets, managed rotation, audit attestation** have **no detection at all** — they are
  wired unconditionally in `DependencyInjection.cs` and run regardless of tier. They are invisible to
  licensing.
- `LicenseStartupCheck` logs status and writes one soft audit row **only when `Status != Valid`**. It
  never surfaces the common case: a **valid Community** license running Max-only features.

Net effect: "Max-only" is currently unenforced *and* half-unobserved. This design makes every paid
feature produce a consistent, auditable signal when it runs unlicensed or beyond tier — **without ever
changing behavior**.

## 2. Goals / Non-goals

**Goals**
- Complete, consistent, auditable surfacing of **all six** paid features when running unlicensed or
  beyond the current tier.
- A **single source of truth** for config-active premium-feature detection (kill the inline strings).
- Close the "valid-Community-using-Max-features is invisible" gap.

**Non-goals (explicitly out)**
- Disabling or degrading any feature (enforcement is **soft only** — locked in GTM_STRATEGY §2).
- Any new UI (the existing banner stays; no per-feature badges, no License-page changes).
- Gating **KEK rotation** (`KekRotationService`) — that is baseline security, not a paid feature.
- Touching the secret **read/decrypt** path, or introducing any phone-home.

## 3. Invariants (must hold — verify in tests)

1. **Licensing never blocks the vault.** Nothing here is consulted on the secret read/decrypt path.
2. **Behavior is byte-identical** whether licensed or not — only signals (log lines, audit rows)
   differ. A lease still mints, a rotation still runs, a checkpoint still signs.
3. The usage recorder **never throws**; a failed audit write is logged and swallowed
   (`AuditWriteFailedException`), mirroring `LicenseStartupCheck`.
4. **Development is never nagged or recorded** (it runs unlicensed by design — no pinned key).
5. No audit spam: on-demand signals are **deduped to once per feature per process**.

## 4. Feature classes

| Feature key         | Class      | Activation signal                                   | Surface point                                   |
|---------------------|------------|-----------------------------------------------------|-------------------------------------------------|
| `kms`               | config     | `CryptoOptions.Engine == VaultTransitCryptoEngine.EngineName` | startup                                |
| `redis-ha`          | config     | `RedisOptions.Enabled == true`                      | startup                                         |
| `sso`               | config     | `SsoOptions.Authority` non-empty                    | startup                                         |
| `dynamic-secrets`   | on-demand  | a lease is issued                                   | `DynamicSecretService.IssueAsync`               |
| `managed-rotation`  | on-demand  | a managed secret is rotated                         | `SecretService.RotateManagedAsync`              |
| `audit-attestation` | on-demand  | a checkpoint is signed                              | `AuditCheckpointService.CreateCheckpointAsync`  |

Keys are the existing constants in `EclipsVault.Core/Application/Licensing/LicenseFeatures.cs`.

## 5. Mechanism A — config-toggled features (surfaced at startup)

### 5.1 `ConfiguredPremiumFeatures` (new)

- **Location:** `EclipsVault.Infrastructure/Security/Licensing/ConfiguredPremiumFeatures.cs`
- **Lifetime:** singleton, registered in `AddEclipsVaultInfrastructure`.
- **Dependencies (all already registered):** `IOptions<CryptoOptions>`, `IOptions<RedisOptions>`,
  `IOptions<SsoOptions>`.
- **Surface:** `IReadOnlySet<string> Active { get; }` — computed once from the bound options:
  - add `LicenseFeatures.Kms` when `CryptoOptions.Engine == VaultTransitCryptoEngine.EngineName`;
  - add `LicenseFeatures.RedisHa` when `RedisOptions.Enabled`;
  - add `LicenseFeatures.Sso` when `SsoOptions.Authority` is non-empty.
- Uses the strongly-typed options and the `EngineName` constant — **not** raw config strings — so it
  can't drift from how the engine is actually selected.

### 5.2 Consumers

- **Banner builder** (`Program.cs`): delete the inline detection block; resolve
  `ConfiguredPremiumFeatures` and pass `Active` into `LicenseNudgeState.From(license, active)`.
  Behavior of the banner is unchanged; it just reads the single source now.
- **`LicenseStartupCheck`** (`EclipsVault.Infrastructure/Workers/LicenseStartupCheck.cs`): inject
  `ConfiguredPremiumFeatures`. Expand the trigger from `Status != Valid` to:
  > record when `Status != Valid` **OR** any feature in `Active` is not `license.Allows(feature)`.

  - Keep the existing `AuditAction.LicenseInvalidProductionUse` row for the **whole-license-invalid**
    case (unchanged).
  - When the license *is* Valid but `Active` contains features beyond it, write a **separate** row
    with `AuditAction.LicenseFeatureUnlicensed`, `ResourceType = "License"`,
    `ResourceName = "<comma-joined beyond-tier feature keys>"`, `IsCritical = false`,
    `ActorUsername = "system"`. Development still returns early (invariant 4).

## 6. Mechanism B — on-demand features (surfaced at the call site)

### 6.1 `IPremiumFeatureUsage` (new Core abstraction)

- **Location:** `EclipsVault.Core/Application/Abstractions/IPremiumFeatureUsage.cs`
- **Surface:** `Task RecordUseAsync(string featureKey, CancellationToken ct)`.
- Lives in Core because two of the three call sites (`DynamicSecretService`, `SecretService`) are Core
  services and may only depend on Core abstractions.

### 6.2 `PremiumFeatureUsageRecorder` (new Infrastructure impl)

- **Location:** `EclipsVault.Infrastructure/Security/Licensing/PremiumFeatureUsageRecorder.cs`
- **Lifetime:** singleton (holds the process-wide dedup set), registered in
  `AddEclipsVaultInfrastructure`.
- **Dependencies:** `ILicenseState` (singleton), `IServiceScopeFactory` (to obtain a scoped
  `IAuditSink` per emission — the exact pattern `LicenseStartupCheck` uses), `ILogger`. A
  `ConcurrentDictionary<string, byte>` (or `HashSet` behind a lock) for dedup.
- **`RecordUseAsync(feature, ct)` logic:**
  1. `if (_license.Allows(feature)) return;` — licensed, nothing to surface (the hot path: a single
     set lookup once entitled).
  2. `if (!_seen.TryAdd(feature, 0)) return;` — already surfaced this process, no repeat.
  3. Log a warning naming the feature.
  4. In a fresh scope, resolve `IAuditSink` and write one row: `AuditAction.LicenseFeatureUnlicensed`,
     `ResourceType = "License"`, `ResourceName = feature`, `IsCritical = false`,
     `ActorUsername = "system"`. Catch and swallow `AuditWriteFailedException` (invariant 3).
  5. Never throws for any reason.

  Note: `Allows()` is `false` for a *Valid Community* license too (Community grants no features), so
  Community deployments that exercise these features are correctly surfaced — matching Mechanism A's
  expanded trigger.

### 6.3 Call sites (one line each)

Place the call **after basic argument/existence validation, immediately before the premium action
actually executes** — so a bad-input early-throw (e.g. unknown role id) does not record a use, but any
genuine attempt to mint/rotate/sign does. Dedup makes the attempt-vs-success distinction immaterial
after the first hit, so no need to thread it to the success path.

- `DynamicSecretService.IssueAsync` → `await _premiumUsage.RecordUseAsync(LicenseFeatures.DynamicSecrets, ct);`
  (after the role-exists / `IsEnabled` checks, before backend mint)
- `SecretService.RotateManagedAsync` → `... RecordUseAsync(LicenseFeatures.ManagedRotation, ct);`
- `AuditCheckpointService.CreateCheckpointAsync` → `... RecordUseAsync(LicenseFeatures.AuditAttestation, ct);`

Each of these three services gains an `IPremiumFeatureUsage` constructor parameter (so their existing
test builders/factories gain the new arg — expected churn). Because the call is fire-safe and returns
quickly, it cannot alter the surrounding operation.

## 7. Audit taxonomy change

- Add **one** value to `EclipsVault.Core/Domain/Enums/AuditAction.cs`: `LicenseFeatureUnlicensed`.
  - Used by the call-site rows (§6.2) and the "feature beyond tier" startup row (§5.2).
  - `LicenseInvalidProductionUse` is retained for the whole-license-invalid startup case.
- Follows the one-enum-per-file convention already in the repo.
- If any activity describer / audit-reader switch statement enumerates `AuditAction`, add a
  human-readable description for the new value there too (grep for existing `LicenseInvalidProductionUse`
  handling and mirror it).

## 8. DI registration summary (`AddEclipsVaultInfrastructure`)

```
services.AddSingleton<ConfiguredPremiumFeatures>();
services.AddSingleton<IPremiumFeatureUsage, PremiumFeatureUsageRecorder>();
```

`Program.cs` banner builder resolves `ConfiguredPremiumFeatures`; `LicenseStartupCheck` gains it as a
ctor dependency.

## 9. Testing plan

**New unit tests**
- `ConfiguredPremiumFeatures`: each option toggled → correct key present/absent; nothing set → empty
  set; multiple set → all present.
- `PremiumFeatureUsageRecorder`: licensed → no audit write; unlicensed → exactly one write with the
  right action + `ResourceName`; second call for the same feature → no second write; different feature
  → its own single write; audit sink throwing `AuditWriteFailedException` → swallowed, no throw.
- `LicenseStartupCheck` (extend existing `LicenseStartupCheckTests`): valid Community + `redis-ha`
  active → writes a `LicenseFeatureUnlicensed` row naming `redis-ha`; valid Max + same active → no
  row; Development → no row.

**Call-site behavior tests (extend existing service tests)**
- `DynamicSecretServiceTests`, `ManagedRotationTests`, and the attestation service tests: with an
  unlicensed `IPremiumFeatureUsage` stub, the operation still completes unchanged **and** records
  usage exactly once; with a licensed stub, it completes and records nothing.

**Regression**
- All existing **434** tests stay green; build stays **0 warning / 0 error**.

## 10. Files touched (estimate)

*New (4):* `ConfiguredPremiumFeatures.cs`, `IPremiumFeatureUsage.cs`,
`PremiumFeatureUsageRecorder.cs`, plus test files.
*Edited (~7):* `AuditAction.cs`, `DependencyInjection.cs`, `Program.cs`, `LicenseStartupCheck.cs`,
`DynamicSecretService.cs`, `SecretService.cs`, `AuditCheckpointService.cs` (+ an activity/audit
describer if one enumerates `AuditAction`).

## 11. Out of scope / follow-ups

- `MintCommand --months` granularity for 3–6-month one-time windows (GTM_STRATEGY §9, task #3) — a
  separate small change.
- Any UI surfacing (License-page view, per-feature badges) — deferred by decision; can be layered on
  later without touching this design.
