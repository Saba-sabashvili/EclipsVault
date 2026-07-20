# EclipsVault — Product & Go-to-Market Roadmap

*Internal planning document. Not for publication. Owner: Saba Sabashvili (solo).*
*Created 2026-07-19. Horizon: ~12 weeks to a buyable two-tier product, then steady state.*

## Business model (settled)

- **Digital product, sell forever.** No SaaS ops, no per-seat billing, no hosting.
- **Two public tiers: Community (free) and Max (paid).**
- **Max is a perpetual license** to the major version bought, **plus 12 months of feature
  updates**, renewable to keep receiving new versions. Don't renew → keep what you have; it
  keeps working forever.
- **Security patches are always free** to any supported major version, regardless of update
  status. This is a promise and a differentiator, never a paywall.
- **Enforcement is SOFT.** A license problem shows a banner; it never stops the vault serving
  secrets or disables already-configured features. (A security tool that outages on a license
  hiccup is unsellable.)
- **Sold via a Merchant of Record** (Polar) so EU VAT is handled.

### The three distinct "gates" — do not conflate them

| Mechanism | What it controls | When it acts | If it fails |
|---|---|---|---|
| **Tier gate** (Community vs Max) | which features *exist* (SSO, KMS, HA, dynamic secrets, rotation, attestation) | runtime, per feature entry point | feature simply unavailable — this is not "soft", it's just the tier |
| **License validity** (signature/malformed) | trust in the Max key | runtime | **SOFT** — banner only; every already-working feature keeps working |
| **Update window** (12 months) | access to *newer builds* | download/update time only | you keep your current version + all security patches; only new *feature* releases are withheld |

**Critical correctness rule:** a perpetual Max license must never runtime-expire into Community.
The update window is enforced at the update channel, not by disabling features. See Phase 1.

## Tier split (proposed — the one decision to confirm)

Baseline security is **complete and identical in both tiers**. Max adds scale, integrations,
compliance artifacts, and support. This keeps the free tier genuinely trustworthy (it *is* the
marketing and the audit substitute) and makes Max compelling to the real buyer: a small,
compliance-driven team without a platform engineer.

| Capability | Community (free) | Max (paid) |
|---|:---:|:---:|
| Envelope encryption (AES-256-GCM, per-secret DEK, AAD binding) | ✓ | ✓ |
| MFA: TOTP + passkeys/WebAuthn, step-up auth | ✓ | ✓ |
| ABAC engine (clearance × sensitivity × project × network × time) | ✓ | ✓ |
| Tamper-evident audit chain **+ offline verifier** | ✓ | ✓ |
| Honey-token decoys / intrusion response | ✓ | ✓ |
| Secret CRUD, versioning, expiry, sharing, API keys | ✓ | ✓ |
| Strict CSP + transport-header posture | ✓ | ✓ |
| SQL Server **or** PostgreSQL, single node | ✓ | ✓ |
| **SSO / OIDC** (`sso`) | — | ✓ |
| **External KMS for the KEK** — Vault Transit (`kms`) | — | ✓ |
| **Redis-backed HA / multi-node** (`redis-ha`) | — | ✓ |
| **Dynamic secrets** — minted short-lived DB creds (`dynamic-secrets`) | — | ✓ |
| **Managed rotation** — rotates the real upstream credential (`managed-rotation`) | — | ✓ |
| **Signed compliance attestation export** (`audit-attestation`) | — | ✓ |
| Priority security patches + email support | — | ✓ |
| 12 months of feature updates (renewable) | — | ✓ |

**Community cap: feature-based, not metered.** Do **not** cap the number of secrets/users — "you
can't add your 51st secret" is a terrible look on a vault and punishes the exact adoption you
want. Community is limited by *which features it has*, not *how much it holds*.

**→ Decision to confirm before Phase 1:**
1. Keep Community usable in production, or restrict it to non-production/eval (the enum comment
   currently says "free, non-production")? Recommendation: **allow small production use** — a happy
   free prod user is your best word-of-mouth and the funnel to Max. A non-prod restriction is
   unenforceable under soft enforcement anyway.
2. Confirm the six gated features above, or move any of them into Community.

## Current state (what already exists — do not rebuild)

- Security core: envelopes/AAD, WebAuthn RP, TOTP, Argon2id, ABAC, audit chain + `AuditBundleVerifier`,
  honey tokens, dynamic secrets, managed rotation, Redis HA, Vault Transit — **built and reviewed.**
- Licensing: `LicenseForge` (offline minting CLI), `LicenseVerifier` (offline, side-effect-free),
  `LicenseClaims`, `LicenseFeatures`/`LicenseTierFeatures`, `LicenseNudgeState`, `LicenseController`.
  The model already refuses to gate base security. **The machinery exists; the call-site gates and
  the two-tier packaging do not yet.**
- Docs drafted: threat model, incident response, backup/recovery, privacy, commercial terms, install.
- CI: keyless cosign signing of release images + signed SBOM; pinned base images.

**Implication: the remaining work is packaging, gating, store, and trust — not features.**

---

## Phase 0 — Decide & draw the line  *(this week)*

- [ ] Confirm the tier split and the two Community decisions above.
- [ ] Collapse `LicenseTier` to **{ Community, Max }** (keep an internal `Enterprise`/custom value if
      you want room for bespoke deals, but sell two). `Max` grants **all six** features.
- [ ] Finalize price. Starting point: **Max $399 one-time / organization** (perpetual + 12 mo
      updates), renewal ~$180/yr for continued updates. Revisit after the first 10 sales.
- **Deliverable:** a one-page pricing + feature-matrix decision, and an updated tier enum.
- **Why first:** every downstream task (gating, store, landing copy) depends on this line.

## Phase 1 — Make the split real in code  *(weeks 1–3)*

- [ ] Set `Max` → all features in `LicenseTierFeatures`; remove/retire `Pro`.
- [ ] **Wire the gate at each feature entry point** (this is the actual work — the flags are modeled
      but enforcement is thin): SSO login, Vault Transit KEK provider selection, Redis HA wiring,
      dynamic-secret issuance, managed-rotation trigger, attestation export. Each checks the
      effective feature set; absent → feature is unavailable with an "available in Max" nudge.
- [ ] **Separate perpetual from update-window in the claims.** Add `UpdatesUntilUtc`; make Max
      licenses perpetual (`NotAfterUtc = null` for runtime). `LicenseVerifier` must **never** downgrade
      a signed Max key to Community on date grounds — a lapsed update window is a nudge, not a
      feature loss. Add a test that pins this.
- [ ] Confirm soft enforcement end-to-end: invalid/expired/malformed key → banner via
      `LicenseNudgeState`, secrets still served, configured features still work.
- **Deliverable:** no key → secure Community; Max key → all features; lapsed update window → still
      Max, with a renew banner. Tests cover all three.

## Phase 2 — Two security fixes that are sales assets  *(weeks 2–4, parallel)*

- [ ] **Verifier key-pinning:** `EclipsVault.AuditVerifier` gains `--expected-key` and fails unless
      the bundle's signing key matches. Closes the "insider re-signs with their own key" gap and
      makes the offline-proof claim actually true.
- [ ] **Audit signing-key separation:** get `ECLIPSVAULT_AUDIT_SIGNING_KEY` off the app host for Max
      deployments (external signer / documented HSM path), so "tamper-evident even against an
      insider" survives an insider with host env access. At minimum, document the current limit
      honestly in the threat model.
- [ ] **Honey-token blast radius:** block the exact host by default; make /24–/64 range-blocking an
      opt-in. Prevents one compromised low-priv session from DoSing a whole NAT/VPN egress.
- **Why here:** these harden the *one claim that differentiates you*. They are compliance/Max
  selling points, not features — worth doing before the landing page makes the claim.

## Phase 3 — Store & delivery  *(weeks 3–5)*

- [ ] Polar account + Max product; connect payout/tax.
- [ ] License-key delivery on the purchase webhook (mint with `LicenseForge`, email the key +
      `UpdatesUntilUtc`). A minimal license portal: view/download key, see update window, renew.
- [ ] Publish the **Community** image to GHCR + Docker Hub; publish "verify before you run" (cosign)
      instructions front-and-center.
- [ ] One-page landing: repositioned pitch ("compliance-ready self-hosted secrets for the team
      without a platform engineer"), the feature matrix, honest boundaries, buy button.
- **Deliverable:** a stranger can buy Max and receive a working key; anyone can pull Community.

## Phase 4 — Trust & launch content  *(weeks 4–6)*

- [ ] Publish threat model **including "what this does NOT protect against."**
- [ ] Publish 2–3 architecture writeups you've already written (AAD binding; the audit-chain
      SaveChanges failure bug; honey-token design). This is your audit substitute.
- [ ] Quickstart / install / backup-and-recovery docs polished for a first-time operator.
- **Deliverable:** a credible public presence that answers "why should I trust a solo vault?"

## Phase 5 — First 10 customers & feedback loop  *(weeks 6–12)*

- [ ] Post the honest "I built a self-hosted Vault alternative" to r/selfhosted, r/homelab, HN,
      Lobsters. Lead with the writeups, not the sales page.
- [ ] Onboard early users; **talk to every one.** Log every feature request and every objection.
- [ ] List on low-friction marketplaces in order: Cloudron → Elestio/Coolify → DigitalOcean →
      Unraid. (Skip AWS Marketplace and any SOC 2 effort until there's demand pulling for it.)
- **Deliverable:** 10 buyers — or the evidence the thesis is wrong, which is equally valuable — and
  a demand-driven backlog that replaces guesswork.

## Phase 6 — Steady state (post-launch, ongoing)

- **2 paid feature releases/year** during the update window; **security patches always free.**
- Quarterly customer conversations set the roadmap. Build what buyers ask for, not what's fun.
- Revisit price once you have 10–20 sales of signal.

---

## Explicitly deferred — do not rathole on these now

- SOC 2 / third-party audit (revisit when a paying customer *requires* it and will fund it).
- AWS/Azure enterprise marketplaces (paperwork-heavy, wrong early audience).
- Remaining UI-proposal items (inline step-up drawer, recovery-code PDF, sparklines) — polish, not
  revenue. Ship after first customers if they ask.
- The unmerged branch stack and the two competing visual directions — resolve as engineering
  hygiene, separately from this go-to-market track (see the session handoff).
- Any new security *primitive*. The core is enough to sell. More hand-rolled crypto is more patch
  surface for one person.

## The one honest risk to keep in view

"Create once, sell forever" is right for you everywhere **except** the security-patch obligation,
which is unbounded and yours alone. The model above contains it: security patches are free and
scoped to *supported* major versions, support is best-effort (say so in the commercial terms, cap
liability at fees paid), and the source-available continuity clause covers your disappearance. Keep
that boundary explicit in every customer-facing document. It is the difference between a sustainable
solo product and a liability with your name on it.
