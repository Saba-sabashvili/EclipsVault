# Incident response

A one-page runbook for handling a reported security weakness. [`SECURITY.md`](../SECURITY.md) is what
a *reporter* reads; this is what *you* do when a report arrives. Write the decisions down now, while
calm — an incident is the wrong time to invent a process. EclipsVault is self-hosted, so you cannot
patch a customer's instance for them: your job is to fix fast and give operators what they need to act.

## Severity (decide this first)

| Level | Meaning | Example | Target fix |
|---|---|---|---|
| **Critical** | Secrets exposable, auth bypass, audit forgeable — with a plausible path | Pre-auth decryption; ABAC bypass; audit chain forgeable undetected | 72 hours |
| **High** | Real compromise needing some precondition | Privilege escalation by an authenticated low-priv user; session fixation | 7 days |
| **Medium** | Limited impact or high precondition | Info leak of metadata; denial of service on one endpoint | 30 days |
| **Low** | Hardening / defense-in-depth | Missing header; verbose error | Next release |

Judge by *impact on the in-scope assets* in [`THREAT_MODEL.md`](THREAT_MODEL.md). If a report targets
something **out of scope** (a compromised host, KEK loss, deployment config), it is a boundary
discussion, not an incident — reply, explain the boundary, and log it, but the clock below does not run.

## The flow

1. **Acknowledge** (within a few business days, per SECURITY.md). Confirm receipt, ask for anything
   missing to reproduce. Do not commit to a fix or a date yet.
2. **Reproduce & triage.** Reproduce against an evaluation instance. Assign a severity. If you cannot
   reproduce, say so and keep the thread open — do not close as "works for me."
3. **Contain / assess blast radius.** Is it exploitable in a default configuration? Does a
   configuration change mitigate it in the meantime? If there is an interim mitigation operators can
   apply *today*, that is the most valuable thing you can send before the patch exists.
4. **Fix, with a regression test.** Reproduce the bug as a failing test first (red), then fix (green),
   so the vulnerability can never silently return. This is non-negotiable for a security fix.
5. **Release.** Cut a patched version. Note the fix in the release notes. Keep the security detail
   terse until operators have had time to upgrade (see disclosure timing).
6. **Notify operators** — the step self-hosting makes essential. Announce through the security channel
   (see below) with: affected versions, severity, the fixed version, any interim mitigation, and
   whether exploitation requires a precondition. Operators cannot act on a fix they never hear about.
7. **Disclose.** Credit the reporter (if they want it), publish the advisory, and — where it applies —
   request a CVE. Standard coordinated timing: **up to 90 days**, or sooner once a fix is released and
   operators have had a reasonable upgrade window. Bring it forward if there is evidence of active
   exploitation.
8. **Post-incident.** One honest paragraph to yourself: how did it get in, what would have caught it,
   what changes (a test, an analyzer rule, a doc). Fold that back into the codebase.

## Reaching operators (the outbound channel)

The gap SECURITY.md does not close: it handles reports *coming in*; you also need a way to push a
warning *out*. Before the first real sale, stand up **one** of:

- a low-volume security-announce mailing list operators opt into at purchase, and/or
- signed, published release notes / a GitHub "Security advisories" feed operators can watch.

Record who has bought a license (the MoR gives you buyer emails) so a Critical advisory can reach
every current operator directly, not just those who happen to check the repo.

## Your own trust roots (do not skip in a rush)

Release images are signed **keyless** (Sigstore) by the GitHub Actions release workflow's identity, so
there is no release-signing key to leak. The trust root is instead the **GitHub account, repository, and
release workflow** — anyone who can push a `v*` tag or alter `.github/workflows/release.yml` can get a
legitimately-signed malicious image. So an incident touching CI is a supply-chain incident: enable 2FA,
protect the default branch and tags, review any workflow change, and if the account or a maintainer
credential is compromised, treat every release since as suspect, publish which digests are trusted, and
say so in the advisory.

The one long-lived secret that remains is the **vendor license private key**. A leak there is
low-impact — enforcement is soft, so a forged license cannot unlock anyone's data — but rotate it
anyway: re-issue from a fresh key, ship the new public key in a release, and note it in the advisory.
