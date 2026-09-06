# Premium-Feature Activation Gate — Design

**Date:** 2026-09-06 · **Status:** approved design, pre-implementation
**Related:** `docs/internal/STRATEGY_DECISION.md` (Pillar 4). This is the **first cut**: it gates only
the two lockout-proof features. SSO is a deliberate follow-up (see *Out of scope*).

---

## Goal

Move non-payment for premium features from **passive and silent** to **an affirmative act**: a customer
running a gated feature without a licence (trial or paid) is *refused*, not merely noted. This raises
enforcement from "trust the operator's honesty" to "circumvention requires editing the source" — the
practical ceiling for source-available software — while never risking a vault outage.

The trial token from the prior increment (`mint --trial-days <n>`) is what *lifts* the gate: a valid
Max licence (trial or paid) grants the feature and the gate is transparent.

## Scope

**In (this cut):** gate **dynamic secrets** (refuse to *issue new* leases) and **managed rotation**
(refuse to *rotate the real backend credential*) when the resolved licence does not grant them.

**Out (this cut):**
- **SSO** — gating it risks locking out SSO-only orgs; it needs a "local admin login always available"
  safeguard designed on its own. Deferred.
- **KMS, Redis HA, audit attestation** — stay **soft** (record-only), unchanged. Gating stateful /
  trust features can lock data or is user-hostile.
- Self-serve trial-key issuance — trials remain vendor-minted (`MINT_RUNBOOK.md`).

## Design (chosen approach: promote the existing seam)

Both target features already call `IPremiumFeatureUsage.RecordUseAsync(feature)` at their point of use
(`DynamicSecretService.IssueAsync`, `SecretService.RotateManagedAsync`). The gate promotes that same
seam rather than adding a parallel enforcement path.

### 1. The gated set — single source of truth
A set of hard-gated feature keys, defined once in Core:
`LicenseFeatures.Gated = { DynamicSecrets, ManagedRotation }`.
Anything not in the set stays soft. Adding SSO later is one entry here (plus its lockout safeguard).

### 2. The enforcement method — `IPremiumFeatureUsage.RequireAsync(feature, ct)`
Added alongside the existing `RecordUseAsync` (which stays for the soft-only callers, so each call site
reads truthfully — "record" vs "require"). Behavior:

- `license.Allows(feature)` is **true** → return immediately (entitled; nothing recorded). Hot path.
- Otherwise → write **one** audit row per feature per process (deduped, best-effort, swallowing audit
  errors exactly as the recorder does today), then:
  - if `feature ∈ LicenseFeatures.Gated` → the row's action is **`LicenseFeatureBlocked`**, and it
    **throws `PremiumFeatureNotLicensedException(feature)`** on **every** call (only the audit row is
    deduped, never the refusal);
  - else → the row's action is **`LicenseFeatureUnlicensed`** (today's behavior) and it returns (soft).

`RecordUseAsync` and `RequireAsync` share a private helper for the deduped audit write.

### 3. Call-site changes
- `EclipsVault.Core/Application/DynamicSecrets/DynamicSecretService.cs` `IssueAsync` — swap
  `RecordUseAsync(DynamicSecrets)` → `RequireAsync(DynamicSecrets)`, positioned **before** any
  credential is minted or lease row created, so a refusal leaves nothing half-done.
- `EclipsVault.Core/Application/Secrets/SecretService.cs` `RotateManagedAsync` — swap
  `RecordUseAsync(ManagedRotation)` → `RequireAsync(ManagedRotation)`, before the backend is touched
  (it is already early, line ~177).

### 4. Web mapping & UX
- `PremiumFeatureNotLicensedException` (new, `EclipsVault.Core/Domain/Exceptions/`) is mapped — in the
  two controllers that reach these paths (`SecretsController` rotate-managed; the dynamic-secret issue
  action) or a shared exception filter if one already exists — to **HTTP 402 Payment Required** with a
  clear message: *"Dynamic secrets require a licence. Start a free 30-day trial or install your
  licence."* (feature-specific wording).
- **Proactive state:** the two feature entry points check `license.Allows(feature)` and render a
  "requires a licence" nudge / disabled control, so a user sees it *before* acting, not only on the
  refusal. Reuses the same `ILicenseState` the banner already uses — no new state source.

### 5. Audit
New non-critical `AuditAction.LicenseFeatureBlocked`, written when a gated action is refused, so the
tamper-evident trail shows the vault actually **refused** (distinct from the existing
`LicenseFeatureUnlicensed`, which marks soft, unblocked use). Never `IsCritical` — a licensing refusal
is not a security incident.

## Safety invariants (must hold; asserted by tests)

- **Fail-open, never lock out.** Only *issuing new* leases and *re-rotating* are gated. Existing
  dynamic-secret leases keep working and stay **revocable** while unlicensed; a managed secret keeps
  its **current value** (only re-rotation is refused). Nothing at rest becomes unreadable.
- **The secret read/decrypt path is never touched** by the gate.
- **A licensing check must never itself crash the vault.** The audit write on refusal is best-effort
  and swallowed; the only thing that propagates is the typed `PremiumFeatureNotLicensedException`,
  which the Web layer turns into a 402 — never a 500.
- **Non-gated features are provably unaffected** (KMS/HA/attestation stay soft).

## Testing strategy

- **Core (`PremiumFeatureUsage`):** `RequireAsync` throws for a gated feature when unlicensed; returns
  for a gated feature when licensed; records-only-and-returns (never throws) for a non-gated feature
  when unlicensed; the refusal is not deduped (throws every call) while the audit row is (one/process).
- **`DynamicSecretService.IssueAsync`:** refuses (throws, mints nothing) when unlicensed; issues when
  licensed. (Extends existing `DynamicSecretServiceTests`.)
- **`SecretService.RotateManagedAsync`:** refuses (throws, backend untouched, stored value unchanged)
  when unlicensed; rotates when licensed. (Extends existing `ManagedRotationTests`.)
- **Fail-open regression:** attestation/KMS/HA `RecordUseAsync` still returns without throwing when
  unlicensed.
- **Existing revoke-lease path** still succeeds when unlicensed (no-lockout invariant).
- Web mapping is asserted at the controller level; avoid `WebApplicationFactory` integration tests
  (known dead end in this repo).

## Files touched (estimate)

- `EclipsVault.Core/Application/Licensing/LicenseFeatures.cs` — add `Gated` set.
- `EclipsVault.Core/Application/Abstractions/IPremiumFeatureUsage.cs` — add `RequireAsync`.
- `EclipsVault.Core/Domain/Exceptions/PremiumFeatureNotLicensedException.cs` — new.
- `EclipsVault.Core/Domain/Enums/AuditAction.cs` — add `LicenseFeatureBlocked`.
- `EclipsVault.Infrastructure/Security/Licensing/PremiumFeatureUsageRecorder.cs` — implement
  `RequireAsync`; extract shared audit helper.
- `EclipsVault.Core/Application/DynamicSecrets/DynamicSecretService.cs` — use `RequireAsync`.
- `EclipsVault.Core/Application/Secrets/SecretService.cs` — use `RequireAsync`.
- `EclipsVault.Web/Controllers/SecretsController.cs` + the dynamic-secret issue controller — map to 402.
- The two feature views — proactive nudge.
- Activity/description mapping for the new audit action (`ActivityDescriber`, `AuditViewModels`).
- Tests as above.

## Out of scope / follow-ups

1. **SSO gate + "local admin login always available" safeguard** — the next increment.
2. **Self-serve trial issuance** — a customer-facing "start trial" flow that mints a token without
   vendor involvement.
3. Revisiting whether managed rotation should ever run from a scheduler (today it is user-initiated
   only; if a scheduler is added, the gate there must *skip-and-log*, not throw).

## Decisions & open questions

- **Refusal status: 402 Payment Required** (decided 2026-09-06). It names the actual condition; the
  gate is a payment/entitlement boundary, not an authorization failure.
- *Open:* message copy and the exact "start a trial" contact/route — ties into the commercial-docs
  blockers; use a clear placeholder message until those are settled.
