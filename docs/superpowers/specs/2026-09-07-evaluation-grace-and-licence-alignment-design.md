# Evaluation grace + licence alignment — design

**Date:** 2026-09-07 · **Status:** approved (Saba, "go with A")

## Why

The activation gate merged in PR #31 contradicts the LICENSE shipped in the same commit. Two ways:

1. **Grant 5 (`LICENSE:51-54`)** — *"The Software does not disable, degrade, or block any capability
   when unlicensed... This is deliberate and permanent."* `README:414` repeats it publicly. The gate
   blocks two capabilities. The clause is unconditional; the data-lockout guarantee is a separate
   sentence after it, so there is no reading under which a 402 refusal complies.
2. **Grant 2 (`LICENSE:38-40`)** — grants *"up to 30 consecutive days of Production Use"* of the
   Licensed Capabilities to assess them, and Grant 1 adds *"No payment, registration, or licence key
   is required."* `RequireAsync` has no grace period: it refuses immediately unless a minted token is
   present. The self-service trial the licence grants cannot be exercised without contacting the vendor.

The gate itself was a deliberate decision (`STRATEGY_DECISION.md` Pillar 4). What was missed is that
the licence text was never amended to match it. The prior spec never mentions LICENSE or README.

## Goal

Make the binary, the LICENSE and the README say the same thing, without giving up either the gate or
the zero-friction trial the funnel depends on.

## Design

**A keyless evaluation window, per capability, started by first use — not by install.**

- Grant 2 grants 30 days to assess *the Licensed Capabilities*. A single global window would give a
  capability first tried on day 40 **zero** evaluation days, which would still breach the grant.
  Per-feature windows honour it and cost one extra row.
- The clock starts on the **first gated use**, not at install, so a vault deployed a year ago in
  Community still gets its full 30 days the first time it reaches for dynamic secrets.
- **Viewing a page never starts a window.** The store exposes a read-only `PeekAsync` for the UI and
  `GetOrStartAsync` for the gate. Merely looking at the dynamic-secrets page must not consume the trial.

### Gate decision table (`RequireAsync`)

| Licence | Feature | Window | Result |
|---|---|---|---|
| grants it | any | — | transparent, nothing recorded |
| no | not in `Gated` | — | soft audit row (unchanged) |
| no | gated | none yet | **start it**, allow, write `LicenseEvaluationStarted` |
| no | gated | active | allow |
| no | gated | expired | `LicenseFeatureBlocked` + `PremiumFeatureNotLicensedException` → 402 |
| no | gated | **store unavailable** | **allow** (fail open) |

**Fail open is not optional.** A licensing lookup that throws must never become the operator's
outage — the iron law from `STRATEGY_DECISION.md` Pillar 4. A broken database therefore grants use
rather than denying it, and the direction of that failure is deliberate.

**The window is resettable and that is fine.** The row lives in the customer's own database; deleting
it restarts the clock. Consistent with soft enforcement — circumvention requires editing the database
or the source, which is the practical ceiling for source-available software. Do not try to defeat it.

## Licence + README amendment

Grant 5 stops promising that nothing is ever blocked, and instead promises the three things that are
actually true and actually matter to a buyer:

- your own data is never withheld — decryption is never gated;
- baseline security is never gated;
- only the **activation** of a Licensed Capability is refused, and only after the evaluation period —
  anything already running keeps running, and existing state stays manageable.

`README:414` changes to match. **The final wording is Saba's plus the outstanding lawyer pass** — the
version applied here is a proposal, and the lawyer review already pending on COMMERCIAL_TERMS /
PRIVACY / DATA_PROTECTION now covers this too.

## Out of scope

1. SSO gate (still needs the "local admin login always available" safeguard).
2. Self-serve trial issuance.
3. Any change to the six-capability list, the price, or the renewal model.
