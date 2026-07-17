# Licensing + go-to-market — design

- **Date:** 2026-07-18
- **Status:** approved (design); pending spec review
- **Branch:** `feat/licensing`

## Context & goal

EclipsVault is production-grade but has **zero commercial machinery**: no license key, no
entitlement, no purchase path. The LICENSE already says production use requires a paid agreement,
but nothing issues, carries, or checks that entitlement. This work adds the missing machinery so the
product can be sold as a **digital product through a Merchant of Record** (Polar / Lemon Squeezy) —
which remits EU VAT on the seller's behalf, letting the author sell as an individual — plus the
supporting trust and packaging artifacts (SECURITY.md, SBOM, Dockerfile, install guide, pricing).

The license reuses the crypto the vault already ships: `AuditBundleVerifier` verifies an
ECDSA P-256 / SHA-256 signature against an embedded public key. A license inverts the key custody —
the **vendor** holds the private key offline and mints licenses; the **app** ships the vendor's
**public** key pinned in and can only *verify*, never *mint*.

## Safety invariant (non-negotiable)

A secrets vault must **never** refuse to decrypt because a license is missing, expired, or invalid.
No license check may exist anywhere near `ICryptoEngine`, `SecretService.Reveal*`, decryption, or the
API read path. A bad license changes **banners, logs, and audit only** — never whether a secret is
served. Enforcement is *soft*: legal license + goodwill, nudged by the UI.

## Pricing & tiers (what the license encodes)

Billed **per production deployment, annually, honor-based** (not per-user — no user telemetry; not
per-node — micro-counting is hostile at this price point). One production install = one Pro license,
however many replicas. Numbers are launch anchors calibrated to indie/self-hosted reality (an unknown
solo vendor with soft enforcement, competing against free OSS), to be confirmed against live pricing.

| Tier | Price (anchor) | Contents | Buyer |
|---|---|---|---|
| **Community** | Free | Non-production / personal / homelab + **60-day** evaluation. Single deployment. All features present (source-available). | Funnel |
| **Pro** | **$249/yr per production deployment** (flex $199–$399) | Production license + SSO, PostgreSQL, dynamic secrets, Redis HA, KMS engine + best-effort email support | SMBs, .NET teams, consultancies |
| **Enterprise / Support** | Custom annual contract — typically low-four-figures (~$1,500+), no fixed anchor | Everything + managed rotation, signed audit attestation, priority security patches / LTS, MSA/DPA, deployment help, invoice billing | Buyers needing paperwork |

Add-ons (where a solo vendor's real margin is): priority/incident support retainer; one-time
deployment/onboarding package. Launch tactic: a **$99 one-time lifetime Pro** for the first ~25
customers, traded for a logo/testimonial, to seed social proof.

`MaxNodes` stays in the license schema for future scale banding, but is generous/unlimited for Pro at
launch — billing is per-deployment, not enforced by node count.

### What the annual fee buys, and continuity

The model is **operationally hands-off, relationally ongoing (light)**. The customer runs everything —
their database, their connection string, their `ECLIPSVAULT_KEK` / KMS, their backups, their TLS — and
the vendor never touches their secrets, keys, or servers. But the annual license is **not** buy-once:
it buys (1) the legal right to run in production, (2) **ongoing security patches**, and (3) best-effort
email support. Security software that stops being patched becomes actively dangerous, so an unmaintained
vault is a real harm — which is exactly what the recurring fee funds. The vendor is *not* operating the
customer's instance, rotating their credentials, holding keys, or on-call for uptime; that stays the
customer's job.

**Continuity clause (the bus-factor answer):** because a self-hosted customer's real dependency is
*patches over time*, the go-to-market copy must state that if the vendor abandons the software, the
license converts to a permissive one (or a source-escrow release triggers) — so the customer keeps the
source and the legal right to patch it themselves or hire someone. This single commitment resolves the
main objection a one-person vault faces. Legal wording is deferred to the author/lawyer; the README
and SECURITY.md carry the positioning.

## Token format

A compact, self-defined string (JWT-shaped, ours):

```
EVLIC1.<base64url(canonical-payload)>.<base64url(ecdsa-p256-sig)>
```

The signature covers the **exact** payload bytes embedded in the token (verification decodes the
payload segment and verifies over those literal bytes, then parses them) — no re-serialization, no
canonicalization ambiguity. `base64url` via `System.Buffers.Text.Base64Url` (BCL, net10).

## Core components (pure, BCL-only — mirrors the audit verifier)

All under `EclipsVault.Core/Application/Licensing/` unless noted. Core has **zero** package
references and does **not** use `System.Text.Json` — the payload is a manual canonical byte layout
exactly like `AuditCheckpointCanonical`.

- `LicenseClaims` (record): `LicenseId, Tier, IssuedTo, Contact?, IssuedAtUtc, NotAfterUtc?, MaxNodes, Features[]`.
- `Domain/Enums/LicenseTier.cs`: `Community, Pro, Enterprise` (one enum per file).
- `Domain/Enums/LicenseStatus.cs`: `Missing, Malformed, InvalidSignature, Expired, Valid`.
- `LicenseCanonical`: deterministic byte layout, 0x1F unit-separator joined (mirrors
  `AuditCheckpointCanonical`); free-text fields (`IssuedTo`, `Contact`) base64'd so they can't
  contain the separator; `Features` joined by commas (keys are `[a-z-]`). Versioned by the `EVLIC1`
  prefix so the layout can evolve.
- `LicenseToken`: encode/decode the `EVLIC1.<payload>.<sig>` string (pure).
- `LicenseVerification` (record): `Status, Claims?, Message`. Returns `Claims` even when `Expired`.
- `LicenseVerifier.Verify(token, pinnedPublicKeySpki, now)`: pure `ECDsa` SPKI-import +
  `VerifyData(SHA256)`, structured exactly like `AuditBundleVerifier`. Order: Missing → Malformed →
  InvalidSignature → Expired → Valid.
- `LicenseFeatures`: feature-key constants (`sso, kms, redis-ha, dynamic-secrets, managed-rotation,
  audit-attestation`) + `LicenseTierFeatures.For(tier)`.
- `LicensePublicKey`: pinned vendor SPKI as a base64 constant. Ships a clearly-marked placeholder;
  the author runs `LicenseForge keygen` once, keeps the private key offline, and pastes the real
  public key here.
- `Application/Abstractions/ILicenseState.cs`: port exposing `Status`, `Claims?`,
  `bool Allows(string feature)`, and the resolved active-premium-feature set.

### Tier → feature mapping (resolved)

Base secret management, local KEK, TOTP, passkeys, audit chain, ABAC are **never** gated/nudged —
they are the product.

- **Community** → none of the premium set.
- **Pro** → `sso, kms, redis-ha, dynamic-secrets`.
- **Enterprise** → Pro + `managed-rotation, audit-attestation`.

`dynamic-secrets` is placed in **Pro** (resolved). A license may carry an explicit `Features[]` that
overrides the tier default (for bespoke Enterprise deals); when empty, the tier default applies.

## Vendor minting tool — new project `EclipsVault.LicenseForge`

Console app, references Core only (mirrors `EclipsVault.AuditVerifier`), **excluded from the shipped
app image**. Living in the source-available repo is safe: reading the minting code cannot forge
licenses (asymmetric signing), exactly as `AuditVerifier` cannot forge audit trails.

- `keygen` → prints a fresh P-256 keypair: private (PKCS#8 base64, kept offline) + public (SPKI
  base64, pasted into `LicensePublicKey`).
- `mint --tier Pro --to "Acme Ltd" --nodes 3 --years 1 [--features sso,kms] [--id <guid>]` → signs
  and prints a token. Private key read from `ECLIPSVAULT_LICENSE_SIGNING_KEY` (never committed).

## App integration — Infrastructure + Web (soft-nudge)

- `EclipsVault.Infrastructure/Security/Licensing/LicenseOptions.cs` (`License` config section):
  - `EnvironmentVariable = "ECLIPSVAULT_LICENSE"` (precedence) → `FilePath = "license.key"` in the
    content root (fallback). Both supported.
  - `DevelopmentPublicKeySpki` — **Development-only** override so dev/tests use an ephemeral key;
    ignored outside Development.
- `EclipsVault.Infrastructure/Security/Licensing/LicenseService.cs` (singleton, implements
  `ILicenseState`): loads the token once (env → file), verifies against the pinned key (or the dev
  override in Development), caches `Status/Claims/Allows`. Re-read requires a restart — same model as
  the KEK.
- DI registration in `EclipsVault.Infrastructure/DependencyInjection.cs`.

### Soft-nudge surfaces (all non-blocking)

1. **Startup log** — Info if Valid; Warning if Missing/Expired/Invalid (same spirit as the KEK /
   AllowedHosts startup warnings).
2. **One audit row at startup** when running **unlicensed or expired in Production** (marked
   critical) — real "ran unlicensed in production" evidence. Adds one `AuditAction` value and its
   `ActivityDescriber` mapping (per code conventions, every action needs a describer). *(Resolved:
   included in v1.)* This row is written **best-effort / fail-soft**: a failure to record it must be
   caught and logged, never allowed to abort startup — the fail-closed audit discipline is for secret
   operations, and a licensing event must never block the vault (safety invariant).
3. **Global banner** on authenticated pages when `Status != Valid`, or when active premium features
   exceed the licensed tier. CSP-clean, reusing the existing banner/flash pattern.
4. **About / License page** (admin) — `LicenseController` + view: tier, issued-to, expiry, node
   allowance, feature list, validity, and "how to buy / where to paste the token."
5. **Premium-over-tier nudge** — at startup, detect *config-active* premium features
   (`Crypto:Engine=VaultTransit`→`kms`, `Redis:Enabled`→`redis-ha`, SSO configured→`sso`); if beyond
   the licensed tier, warn + banner. Usage-based features (`dynamic-secrets`, `managed-rotation`) are
   shown on the License page but not actively nudged in v1 (keeps startup cheap — no DB probe).

## Config surface (new)

```
License:
  EnvironmentVariable: ECLIPSVAULT_LICENSE   # precedence
  FilePath: license.key                       # fallback, relative to content root
  DevelopmentPublicKeySpki: <base64>          # Development only
```

Plus env vars: `ECLIPSVAULT_LICENSE` (the token, deploy-side) and
`ECLIPSVAULT_LICENSE_SIGNING_KEY` (the private key, vendor-side, LicenseForge only).

## Testing

Core tests mirror `SealedSecretTests` / the audit tests, using an in-test ephemeral keypair:

- valid token → `Valid`; tampered payload → `InvalidSignature`; past `NotAfterUtc` → `Expired`;
  bad prefix / base64 / layout → `Malformed`; null/empty → `Missing`; wrong key → `InvalidSignature`.
- `LicenseToken` encode→decode round-trip.
- `LicenseTierFeatures.For` + `Allows` mapping, including the explicit-`Features[]` override.

## Other deliverables

- **`SECURITY.md`** — supported versions, private disclosure channel (`sabashvili13@icloud.com`),
  scope, safe-harbor, response expectations.
- **SBOM in CI** — add a CycloneDX generation step to `.github/workflows/ci.yml`, uploaded as a build
  artifact (fits the existing pin-and-prove supply-chain posture).
- **`Dockerfile` + `.dockerignore`** — production multi-stage build for `EclipsVault.Web`
  (SDK build → `aspnet` runtime), **non-root** user, digest-pinned base images, healthcheck, no dev
  secrets baked in.
- **`docs/INSTALL.md`** — one production runbook consolidating today's scattered README guidance: env
  vars (connection string, `ECLIPSVAULT_KEK`, `ECLIPSVAULT_LICENSE`, DataProtection key-ring path,
  audit signing key), run-migrations-from-deploy-job, TLS / reverse proxy, forwarded headers, and a
  container run example.
- **README "Pricing & licensing" section** — the 3-tier table + how to buy (MoR link placeholder) +
  how to install the license token + what the annual fee buys (patches + best-effort support) + the
  continuity/abandonment commitment. SECURITY.md carries a short version of the continuity line too.

## File / project inventory

- **New project:** `EclipsVault.LicenseForge` (Core-only ref); add to `EclipsVault.slnx`.
- **Core:** `Application/Licensing/` (LicenseClaims, LicenseCanonical, LicenseToken,
  LicenseVerification, LicenseVerifier, LicenseFeatures, LicensePublicKey) + `Domain/Enums/`
  (LicenseTier, LicenseStatus) + `Application/Abstractions/ILicenseState.cs`.
- **Infrastructure:** `Security/Licensing/LicenseService.cs` + `LicenseOptions.cs`; DI wiring; one new
  `AuditAction` + `ActivityDescriber` mapping.
- **Web:** `LicenseController` + `Views/License/Index.cshtml` + global-banner hook in `_Layout` +
  startup wiring (log + conditional audit row).
- **Tests:** `Licensing/LicenseVerifierTests.cs`, `LicenseTokenTests.cs`, `LicenseFeaturesTests.cs`.
- **Repo:** `SECURITY.md`, `Dockerfile`, `.dockerignore`, `docs/INSTALL.md`, CI SBOM step, README
  section.

## Suggested sequencing (for the implementation plan)

1. Core licensing primitives + tests (pure, no app wiring) — provable in isolation.
2. `EclipsVault.LicenseForge` (keygen + mint) — lets the author generate the real keypair and pin the
   public key.
3. App integration: `LicenseService` + `ILicenseState` + DI + startup log/audit + License page + banner.
4. Trust & packaging: `SECURITY.md`, SBOM CI step, Dockerfile, `docs/INSTALL.md`.
5. README "Pricing & licensing" section.

## Out of scope (v1)

- Hard enforcement / feature disabling of any kind.
- Runtime usage metering or phone-home (contradicts the no-egress pitch).
- MoR API integration / automated license delivery (manual mint on sale is fine to start).
- Usage-based nudging for dynamic-secrets / managed-rotation.
