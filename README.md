# 🌒 EclipsVault

A production-grade credentials & secret-management engine built on **ASP.NET Core MVC (.NET 10)** with strict Clean Architecture, envelope encryption, mandatory MFA, attribute-based access control, fail-closed immutable auditing, and active intrusion defence.

## Solution layout

```
EclipsVault.slnx                  # modern XML solution format
├── EclipsVault.Core/             # Pure C#. ZERO package references (BCL only).
│   ├── Domain/                   #   Entities, enums, domain exceptions
│   └── Application/              #   Organised by FEATURE, not by technical kind:
│       ├── Abstractions/         #     infra "ports" (crypto, hashing, TOTP, cache,
│       │                         #       blacklist, revocation, session registry, avatar…)
│       ├── Abac/                 #     pure ABAC rule engine
│       ├── Authentication/       #     sign-in + TOTP workflow, auth DTOs
│       ├── Secrets/              #     secret service, repo port, DTOs
│       ├── Users/                #     user admin service, repo port, DTOs
│       ├── Profile/              #     self-service profile service
│       ├── Networks/             #     trusted-network service
│       ├── Auditing/             #     audit-log reader
│       ├── Dashboard/            #     overview aggregation
│       ├── Activity/             #     per-user activity feed (personal security log)
│       ├── Sessions/             #     signed-in-devices DTOs + pure User-Agent parser
│       ├── SecurityCheckup/      #     per-user posture scoring (pure evaluator + read-model)
│       └── DataExport/           #     personal-data export (self-scoped, metadata-only)
├── EclipsVault.Infrastructure/   # Implements Core interfaces.
│   ├── Persistence/              #   EF Core 10 DbContext, Fluent API Configurations/,
│   │                             #     Repositories/, audit SaveChangesInterceptor,
│   │                             #     Migrations/ (schema source of truth), seeder
│   ├── Security/                 #   grouped into subfolders:
│   │     ├── Cryptography/       #     Argon2id, AES-256-GCM envelope crypto + KEK, TOTP,
│   │     │                       #       API-key factory, audit checkpoint signer
│   │     ├── Defense/            #     IP blacklist + session revocation + session registry
│   │     │                       #       (in-memory AND Redis variants), intrusion response,
│   │     │                       #       trusted networks, breached-password screen
│   │     └── WebAuthn/           #     the passkey relying-party verifier
│   ├── Auditing/                 #   audit checkpoint / export service
│   ├── Distributed/              #   Redis connection options (shared-state switch)
│   ├── Media/                    #   ImageSharp avatar processor
│   ├── Caching/                  #   envelope cache (in-memory AND Redis variants)
│   ├── Logging/ · Workers/
├── EclipsVault.Web/              # Composition root. Thin controllers, ViewModels,
│   ├── Authorization/ · Middleware/ · Services/ · Extensions/ · Views/
├── EclipsVault.AuditVerifier/    # Standalone console tool. Verifies an exported audit
│                                 #   bundle offline — references Core only, no app/DB.
└── EclipsVault.Tests/            # xUnit. Pure-Core invariants: ABAC decision matrix,
                                  #   audit hash-chain, bundle verifier, recovery codes, crypto
```

Dependency rule: `Web → Infrastructure → Core`. Nothing ever points outward. Database entities never leave Infrastructure; controllers see DTOs; views see ViewModels.

**Reproducible, gated builds** — package versions are pinned centrally in `Directory.Packages.props` with committed `packages.lock.json` files (CI restores in `--locked-mode`); `Directory.Build.props` turns compiler/nullable warnings into build errors. `dotnet test` runs the suite; the GitHub Actions workflow (`.github/workflows/ci.yml`) builds, tests, and fails on any vulnerable dependency. Local secrets never enter source control — see *Configuration & secrets* below.

**Application is sliced by feature** (vertical slices inside the layer): each folder holds the interface, its DTOs, and the service for one capability, so a feature is read and changed in one place. Cross-feature references resolve through per-project `GlobalUsings.cs`, so adding a feature folder needs no per-file `using` edits. `Abstractions/` is the exception — it holds the technical "port" interfaces that Infrastructure implements.

**Auditing is a single cross-cutting port.** Every audit row is written through one fail-closed `IAuditSink.WriteAsync(AuditEntry)` (Core.Application.Abstractions → `Infrastructure/Persistence/AuditSink`), not bolted onto repository contracts. Repositories persist their own aggregate only; a service never borrows another aggregate's repository just to record an event. The sink escalates any write failure to `AuditWriteFailedException`, so a secret read that cannot be audited aborts before decrypting (fail-closed). Writes that must be atomic with a data change (secret create/update/shred) are still injected by the `SaveChangesInterceptor`.

**Schema is owned by EF Core Migrations** (`Infrastructure/Migrations/`). Startup runs `Database.MigrateAsync()`; there is no `EnsureCreated` and no hand-written DDL. Add a schema change with:

```bash
dotnet ef migrations add <Name> --project EclipsVault.Infrastructure --startup-project EclipsVault.Infrastructure
```

A design-time `IDesignTimeDbContextFactory` lets the tooling build the context without booting the web host.

## Prerequisites

- .NET 10 SDK
- Docker (for the dependencies below)
- Trusted dev cert: `dotnet dev-certs https --trust` (recommended)

## Run it

The dependencies are all real, open-source (or first-party) services — brought up with one
command rather than mocked in-process:

```bash
docker compose up -d      # SQL Server + Vault + Mailpit + Redis
dotnet run --project EclipsVault.Web
# → https://localhost:7443
```

| Service | Purpose | UI |
|---|---|---|
| **SQL Server** | persistence | — |
| **Mailpit** | captures notification emails (real SMTP) | http://localhost:8025 |
| **HashiCorp Vault** | holds the master key when `Crypto:Engine=VaultTransit` | http://localhost:8200 (`dev-root`) |
| **Redis** | shared distributed state when `Redis:Enabled=true` (opt-in) | localhost:6379 |

(You can still point the app at your own SQL Server / SMTP / KMS via configuration.)

**Configuration & secrets** — the database connection string is deliberately **absent from `appsettings.json`** so credentials are never committed. Local development reads it (plus the dev KEK fallback and seed passwords) from `appsettings.Development.json`, which is git-ignored — copy `appsettings.Development.json.template` to create it. For any real deployment, supply it via the environment (`ConnectionStrings__DefaultConnection`) or a secret store, using a least-privilege SQL login and `Encrypt=True;TrustServerCertificate=False`. Startup fails fast with a clear message if it is missing.

First launch creates and seeds the `EclipsVaultUmbraDb` database ("umbra" — the darkest part of an eclipse's shadow).

| Account | Password | Attributes |
|---|---|---|
| `vault-admin` | `ChangeMe!Umbra#2026-Admin` | TopSecret clearance, project GLOBAL |
| `dev-user` | `ChangeMe!Umbra#2026-Dev` | Standard clearance, project PHOENIX |

Sign in with **either the username or the email** (both seeded accounts also accept their `@eclipsvault.local` email). On first sign-in each account walks through **mandatory TOTP enrollment** (add the displayed key to any authenticator app). No session cookie exists until the second factor passes.

Once a user registers a **passkey** (Profile → Passkeys), the login page offers **“Sign in with a passkey”** for a fully passwordless sign-in — a passkey verifies the user on their device, so it satisfies both factors on its own and skips the password and TOTP steps entirely.

Lost your authenticator? The two-factor step has a **“Use a recovery code”** link. Recovery codes are single-use backup codes you generate from **Profile → Security → Recovery codes** (shown exactly once, stored only as salted Argon2id hashes); one redeems in place of the TOTP code, then is permanently consumed. Resetting the authenticator — by the owner or an admin — invalidates any outstanding codes.

**Emails are generated automatically.** When an admin provisions a user they supply a first and last name; the vault assigns a unique `firstname.lastname.N@<domain>` address, where `N` increments for people who share a name (a second "Saba Sabashvili" becomes `saba.sabashvili.2@…`). The domain is `Identity:EmailDomain` (default `eclipsvault.local`). Email is a unique login identity (enforced by a unique index).

**Account lockout** — after 5 consecutive failed password/TOTP attempts (configurable via `Lockout:MaxFailedAttempts` / `Lockout:LockoutMinutes`) the account is locked for 15 minutes; a successful sign-in resets the counter. Admins see a `Locked` badge in the Users console and can clear it with **Unlock**. This complements the per-IP rate limiter (which throttles the request rate) by throttling per-account guessing.

### Master key (KEK)

In `Development`, a fallback KEK from `appsettings.Development.json` is used (with a loud warning). For anything real:

```bash
export ECLIPSVAULT_KEK="$(openssl rand -base64 32)"
```

Startup fails fast if the KEK is missing or malformed outside Development.

**Rotating the KEK**: generate a new key and set it as `ECLIPSVAULT_KEK`, move the previous key into `ECLIPSVAULT_KEK_RETIRED` (a `;`-separated list — existing DEKs are still unwrapped with it), restart, then run the rotation from the **Encryption keys** admin page. Once it reports everything on the current KEK, the retired key can be removed.

**KMS-backed master key (no KEK in the process)**: set `Crypto:Engine=VaultTransit` and point `Vault:Address` / `VAULT_TOKEN` at a HashiCorp Vault with a Transit key. The master key then lives in Vault — the app only ever holds single-use DEKs, which Vault wraps and unwraps. Locally you can try it with a dev Vault:

```bash
docker run -d --name vault-dev -p 8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=dev-root hashicorp/vault
curl -s -H "X-Vault-Token: dev-root" -X POST -d '{"type":"transit"}' http://127.0.0.1:8200/v1/sys/mounts/transit
curl -s -H "X-Vault-Token: dev-root" -X POST http://127.0.0.1:8200/v1/transit/keys/eclipsvault
Crypto__Engine=VaultTransit VAULT_TOKEN=dev-root dotnet run --project EclipsVault.Web
```

New secrets are then sealed with the Vault-held key (visible as `KekId = vault:eclipsvault:v1`). Switching a database that already holds locally-wrapped secrets is a re-encryption migration; the two engines are not interchangeable per-secret.

### Horizontal scale-out (Redis)

By construction the app holds three pieces of shared runtime state — the **session-revocation** kill switch, the intrusion **IP blacklist**, and the encrypted-**envelope cache**. On a single node these live in process memory. Set `Redis:Enabled=true` and they move behind the same Core interfaces into **Redis**, so the app can run as multiple replicas behind a load balancer: a revocation or block raised on one node is honoured by all of them, and a write on one node evicts the cached envelope everywhere.

```bash
docker compose up -d          # includes Redis on :6379
Redis__Enabled=true dotnet run --project EclipsVault.Web
```

The design keeps the per-request checks cheap: revocation is a single keyed lookup, and because the blacklist keys each block by the offending address's canonical range (`NetworkRules.ToBlockRange` — /24, /64, or an exact loopback host), "is this IP blocked?" is one O(1) key lookup rather than a scan of every block. Verified end-to-end against a real Redis: a revoked session's cookie is rejected across a **full app restart** (in-process state would forget it), and an independent Redis client sees the shared envelope appear on reveal and disappear on rotate. Blocks persist (AOF) across restarts; revocation markers self-expire after `Redis:RevocationRetentionHours` (longer than any session). With `Redis:Enabled=false` (the default) nothing changes and no Redis is required.

## The app

- **Overview dashboard** — secret counts by environment, critical-alert count for the last 24 h, a recent-activity feed (admins see everyone; others see their own actions), and **expiry notifications**: a warning banner plus an "Expiring soon" panel listing secrets within 7 days of their TTL (with a per-item countdown and a one-click Rotate link) so they can be renewed before the lifecycle worker shreds them.
- **Secrets** — searchable list, detail view with one-shot reveal + copy-to-clipboard, guarded delete. Every open/reveal is audited. Revealing a high-sensitivity value on a stale session prompts inline **step-up re-authentication** (a fresh authenticator code) before it decrypts. Admins additionally see a `decoy` badge on honey-tokens with a confirm-gated open.
- **Secret rotation & version history** — rotate a secret's value (with an optional change note); the value it replaces is kept as its own envelope-encrypted `SecretVersion`. A rotation timeline lets you reveal a prior value (audited, fail-closed, before any decryption) or revert to it (which archives the current value first). Versions hold real key material, so they are purged when the secret is shredded or deleted.
- **Secret sharing / access grants** — a secret's project members (and admins) can grant a named user access to that specific secret from its **Sharing** panel, optionally with an expiry. The grantee sees it under **Shared with me** (sidebar) and can open it. A grant crosses the **project boundary only** — the ABAC clearance, network, and time rules still apply, so sharing never widens the clearance ceiling. Grants are consulted live by the ABAC handler, every share/revoke is audited, and grants cascade-delete with the secret.
- **Secret access requests** (sidebar: **Access requests**) — the self-service side of grants. When ABAC denies a secret, its Denied page offers a **Request access** form; the request lands in a review queue for that secret's reviewers (an administrator, or a member of its project). **Approving** creates an ordinary grant for the requester (so the same ABAC rules apply — a grant fixes only a project denial, never clearance/network/time); **rejecting** records the decision. Requesters track their own requests and can withdraw a pending one; the denial reasons are snapshotted onto the request so a reviewer sees exactly what failed. Every transition is audited, and requests cascade-delete with the secret.
- **Notifications / email delivery** (sidebar: **Notifications**, admin) — domain events send email: an access request being approved/rejected notifies the requester, a password change sends a security notice, and provisioning a user sends a welcome. The transport is pluggable behind the Core `IEmailSender` port — **SMTP** for real delivery or a **Log** transport (`Email:Sender`) — and every message is recorded to an **outbox** admins view on the Notifications page (recipient, subject, event, transport, delivery status), which also shows a **delivery-status banner** so it's obvious at a glance whether email is actually being sent and where. In development, `docker compose up` includes **Mailpit** (an open-source SMTP server + web UI), so notifications genuinely deliver — view them at http://localhost:8025. Notifications are **fail-soft**: a delivery failure is captured as a Failed outbox row, never breaking the operation that triggered it.
- **Profile** (every user, self-service) — editable **display name** and email; **profile picture** upload (JPEG/PNG, validated, re-encoded to a safe 256×256 PNG) with a generated identicon fallback; **change password** (current-password check, breached-password screening, Argon2id re-hash); **reset own authenticator**; **generate MFA recovery codes** (single-use backup codes); **register and remove passkeys** for passwordless sign-in; and **sign out everywhere** (server-side session revocation). The login **username is fixed** — it is the audit-trail anchor.
- **My activity** (sidebar: **My activity**, every user) — a personal security log: a plain-language, paged feed of the signed-in user's *own* audit trail — sign-ins (including rejected second factors and recovery-code use), secret reveals, shares, and account changes — newest first, each tagged with a category and a severity accent so notable events stand out. It is scoped **strictly to the caller by user id**, so it discloses nothing about anyone else, and it gives ordinary users (not just admins, who have the global **Audit log**) a way to review their account and spot anything they didn't do. A read-only projection over the same immutable trail — the mapping from raw audit action to friendly wording is a pure, unit-tested Core function (`ActivityDescriber`) that covers every action and degrades gracefully for any added later.
- **Your data** (sidebar: **Your data**, every user) — self-service data access & portability (GDPR-style): every user can see exactly what account and security metadata EclipsVault holds about them — identity, two-step/passkey/backup-code status, signed-in devices, access requests they've filed, and their recent activity — and **download a portable JSON copy**. Strictly self-scoped (the export is always built for the caller's own id) and deliberately **metadata-only**: there is no field anywhere in the export tree that can carry a secret value, ciphertext, key material, a password, a TOTP seed, or a backup code — secret *values* are encrypted and access-controlled and are never exported (a unit test walks the serialized document and fails if any credential-bearing field name ever appears). Downloading is an **antiforgery-protected POST** (so it can't be triggered by a cross-site request or a drive-by prefetch), the response is served `Content-Disposition: attachment` + `Cache-Control: no-store` (never rendered inline, never cached), and the export is **audited** (`PersonalDataExported`) so it shows up in the user's own **My activity** and the global **Audit log**. A pure read-model service composes the export from the existing self-service APIs — no new persistence, no decryption path.
- **Security checkup** (sidebar: **Security checkup**, every user) — a scored, plain-language read on how well the signed-in user's *own* account is protected: four controls — two-step sign-in, one-time backup codes, a phishing-resistant passkey, and how many devices are signed in — each rated Secured / Recommended / Action needed, rolled up into a 0–100 score, a grade (At risk → Fair → Good → Strong), and the single most important next step surfaced first, with a button that deep-links to where it's fixed. The whole scoring model is a **pure, unit-tested Core function** (`SecurityCheckupEvaluator`, weighted controls with severity-ranked output); a thin read-model service composes the posture from the existing account services (profile, passkeys, recovery codes, session registry), each read keyed by the caller's own id so it is **self-scoped by construction** and discloses nothing about anyone else. Read-only — every remediation link points at an existing self-service page. The score ring is rendered with SVG presentation attributes (a computed `stroke-dasharray`), so it fits the strict, no-inline-styles CSP with no escape hatch.
- **Signed-in devices** (sidebar: **Signed-in devices**, every user) — the per-session complement to "sign out everywhere": every user sees each place their account is currently signed in (device, IP, when it signed in, and last-active), with the current one marked, and can **revoke an individual session** (or all the others) without disturbing the device they're on. Each session carries a random id in its cookie; the server keeps a registry of live sessions and a per-session tombstone, and the cookie validator checks it on every request — so a revoked session is rejected on its next request, on **every** node. Strictly self-scoped (every registry call is keyed by the caller's own user id, so a user can only ever see and revoke their own sessions), each revoke is audited (`SessionRevokedByUser`) and shows up in **My activity**. Runtime state, so — like the revocation kill switch and IP blacklist — it is in-process on a single node and **Redis-backed** across a cluster (an atomic Lua upsert throttles the per-request last-seen touch to one round-trip and never resurrects a revoked session).
- **Passkeys / WebAuthn** — register one or more authenticators (Touch ID, Windows Hello, a security key) from the profile, then sign in with no password or TOTP. Registration and assertion are verified server-side (relying-party id hash, origin, challenge, user-verification flag, and the ECDSA/RSA signature over a stored COSE public key), the ceremony challenge is held in a server-side session, and the signature counter is checked on every assertion for cloned-authenticator detection. Every register / sign-in / removal is audited.
- **Administration** (TopSecret clearance only):
  - **Users** — provision accounts (Argon2id + breached-password screening + first-login TOTP enrollment); **edit role** (clearance + project, which revokes the user's sessions so the change applies at next sign-in); **enable/disable** an account (disabling revokes sessions immediately and blocks sign-in); **force logout**; reset a lost authenticator; delete. Guards block disabling/demoting/deleting yourself or the last administrator.
  - **Networks** — shows *your current address exactly as the vault sees it* (on a VPN that's the VPN egress) with a one-click **Trust this address** button. Manage runtime-trusted CIDR ranges (applied immediately, no restart) and lift intrusion-defence IP blocks. Note: network trust is a property of the request's source address, never of a user account.
  - **Service accounts** — provision non-interactive identities (name + clearance + project) for applications; issue **API keys** (shown once, stored only as a SHA-256 hash, optional expiry) — each optionally **scoped** to narrow it below the account (clearance ceiling, single project, or metadata-only); revoke keys; and disable/delete accounts. See the **Programmatic API** below.
  - **Audit log** — filterable viewer over the immutable trail; critical rows highlighted; a **Verify integrity** action re-walks the hash chain and flags any tampering. An **Attestation** panel signs the current chain head into a checkpoint and **exports a signed bundle** that can be verified offline with the `EclipsVault.AuditVerifier` tool.
  - **Encryption keys** — shows which master KEK each secret is wrapped under and runs a **rotation** that re-wraps everything under the current KEK. See *KEK rotation* under Security architecture.

The distinction is clean: **profile** actions only ever touch your own account and can never change clearance or project; **clearance and project are administrative** and live in the Users console. Login username (immutable audit anchor) is separate from the editable display name.
- **Designed empty states** — every list page that can be empty (Shared with me, Access requests, Notifications, Secrets…) renders a reusable `_EmptyState` component — an icon, a heading, a plain explanation of what the page is for, and a call-to-action where one makes sense — so a page with no rows reads as "nothing here yet, here's what it's for" instead of a blank, broken-looking screen.
- **UI foundation** — one app shell (`_Layout` sidebar / `_AuthLayout` centered card), a token-based design system in `site.css` with **light and dark themes** (toggle in the sidebar; the choice is persisted in a cookie and applied server-side on `<html data-theme>` for a flash-free first paint), flash notifications (`FlashExtensions` + `_Flash` partial), and data-attribute behaviours in `site.js` (`data-confirm`, `data-copy`, `data-print`, `data-filter`, `data-flash`, `data-theme-toggle`). New features should compose these pieces: add a controller + views using `page-header`/`panel`/`data-table`, a sidebar entry in `_Layout`, and flash feedback on POST-redirect. Because everything references design tokens, both themes come for free.

## Programmatic API

Applications retrieve secrets over a small JSON API using a **service-account API key** — no browser session, no TOTP. The key is presented as a bearer token, and access is governed by the **exact same ABAC policy** as the interactive UI (clearance, project, network range, and time window all apply).

```bash
# List secret metadata (names only — no values)
curl -H "Authorization: Bearer evk_…" https://localhost:7443/api/v1/secrets

# Retrieve and decrypt one secret's value (ABAC-gated)
curl -H "X-Api-Key: evk_…" https://localhost:7443/api/v1/secrets/<id>
# 200 → { "id": "...", "name": "...", "value": "..." }
# 403 → { "error": "forbidden", "reasons": ["Clearance 'Standard' is below required sensitivity 'Confidential'."] }
# 401 → missing / invalid / expired / revoked key, or the account is disabled
```

Both `Authorization: Bearer <token>` and `X-Api-Key: <token>` are accepted. Every API retrieval is audited against the calling service account, and honey-tokens still trip the intrusion response over the API (returning a bland `404`).

**Per-key scopes** — an individual key can be issued with a scope that narrows it *below* its service account (never above), for least-privilege that is tighter than the account itself:

- **Clearance ceiling** — the key acts with `min(account clearance, ceiling)`, so a TopSecret account can hand out a key that only reaches Internal secrets.
- **Project scope** — pins the key to a single project. This binds even a TopSecret account (which otherwise crosses project boundaries), and also filters what the metadata list returns.
- **Metadata-only** — the key may enumerate metadata (`GET /api/v1/secrets`) but every value read (`GET /api/v1/secrets/{id}`) returns `403`.
- **Network binding (IP allow-list)** — the key may carry a list of source CIDR ranges (e.g. `10.8.0.0/24, 203.0.113.7`); presented from any other address it is rejected outright at authentication with `401`, before the account is even resolved. A leaked key is useless off-network. Enforced against the *real* client IP (see forwarded-headers handling), so it holds behind a load balancer.

Scopes are enforced by the **same pure ABAC engine** as everything else — they simply add deny-rules — so a scoped key can only ever see a strict subset of what the account could. Denials name the exact scope that stopped them (e.g. `"This API key is scoped to project 'PHOENIX'."`), and each key's scope is recorded in its issue audit.

## Security architecture

- **Passwords** — Argon2id (Konscious), 64 MiB / 3 iterations / 4 lanes, unique random 16-byte salt per user, constant-time verify, timing-equalised unknown-user path.
- **Breached-password screening** — every password set (admin provisioning) or changed (self-service) is screened against a compromised-password corpus bundled with the app as an embedded resource and loaded once into a case-folded `HashSet` for O(1) checks. A compromised value is refused with a clear message. The check is fully offline (nothing leaves the process, no HIBP round-trip), and the change-password / create-user forms also run a debounced live check as you type (behind auth + antiforgery; the candidate is only screened in memory, never logged, audited, or stored). Behind the Core `IBreachedPasswordScreen` port, so a full HIBP/SecLists corpus or a k-anonymity range API is a one-class swap. Implements NIST 800-63B §5.1.1.2 and OWASP ASVS 2.1.7.
- **Passkeys / WebAuthn** — a self-contained relying-party implementation (no third-party FIDO2 dependency): the ceremony logic parses CBOR/COSE with `System.Formats.Cbor` and verifies signatures with the BCL's `ECDsa`/`RSA` primitives (ES256 + RS256). User verification is *required*, so a passkey is a genuine two-factor credential; the random challenge lives only in a server-side session (never trusted from the client); origin, relying-party id hash, ceremony type, and the monotonic signature counter are all checked. The relying-party id/name/origins are config (`WebAuthn` section) and the whole thing sits behind the Core `IPasskeyService` port, so swapping in a cloud FIDO2 service is a one-class change.
- **MFA recovery codes** — single-use "look-up secrets" (NIST 800-63B) that stand in for the authenticator when it is unavailable. A generation issues ten codes (~50 bits each, from an unambiguous 32-symbol alphabet), invalidates any prior set, and shows the plaintext exactly once; only a **salted Argon2id hash** per code is stored (below 63B's 112-bit bar, so a moderate-work-factor KDF is mandated). Redemption runs on the same MFA-pending gate as TOTP, verifies against *every* unused code (no early-out timing signal), consumes the matched code, and folds into account lockout and the audit trail (`RecoveryCodesGenerated`, `RecoveryCodeUsed`). Both authenticator-reset paths — self-service and admin — purge outstanding codes so they can't outlive the factor they back up. Migration `AddMfaRecoveryCodes`.
- **Step-up re-authentication** — revealing a secret at or above a configurable sensitivity (`StepUp:MinimumSensitivity`, default Secret) demands a fresh authenticator code when the session's last strong authentication is older than `StepUp:MaxAuthAgeMinutes` (default 10). The reveal is blocked inline until a valid TOTP is entered; a successful step-up refreshes a `vault:stepup_time` claim so the window reopens without re-prompting on every value. The decision is a pure, unit-tested Core rule; both success and failure are audited (`StepUpVerified` / `StepUpFailed`). Implements NIST SP 800-63B §4.2.3 reauthentication and PCI-DSS re-auth for sensitive access.
- **Envelope encryption** — every secret gets a fresh single-use 32-byte DEK; payload sealed with AES-256-GCM; DEK wrapped by the master KEK from the environment; both blobs (`nonce|tag|ct`) stored side-by-side with a `KekId`. Plaintext and DEKs are zeroed (`CryptographicOperations.ZeroMemory`) as soon as possible.
- **KEK rotation & key lifecycle** — the provider holds one *current* KEK plus any number of *retired* KEKs (`ECLIPSVAULT_KEK` + `ECLIPSVAULT_KEK_RETIRED`), each identified by a stable id; a DEK is always unwrapped with whichever KEK sealed it. The admin **Encryption keys** page shows which KEK every secret is on and runs a **rotation** that re-wraps each secret's (and archived version's) DEK under the current KEK — the payload ciphertext is never touched, so no secret is decrypted (honey-tokens included), and shredded tombstones (no key material) are skipped. Aligns with NIST 800-57 cryptoperiods and PCI-DSS 3.6/3.7.
- **Crypto factory & KMS-backed master key** — `CryptoEngineFactory` resolves the engine named by `Crypto:Engine`. Two engines ship: the default local `AesGcmLocal`, and **`VaultTransit`**, which keeps the master key in **HashiCorp Vault** — the payload is still sealed with a local single-use AES-256-GCM DEK, but that DEK is wrapped, unwrapped, and rotated by Vault's Transit engine, so the KEK never exists in process memory, a crash dump, or the database. Switching is one config value (`Crypto:Engine=VaultTransit`) plus a `VAULT_TOKEN`; the business layer is untouched. Each secret records which Vault key version wraps it (`vault:<key>:v<n>`). Addresses the "master key in an env var" gap directly.
- **ABAC** — `AuthorizationHandler<SecretAccessRequirement, SecretDetailsDto>` extracts subject claims (clearance, project), computes runtime context (a configurable time window for Production secrets — UTC by default, or a real IANA zone via `Abac:TimeZoneId` so "business hours" track the org's locale and DST — and a trusted-network check for Confidential+ against static config **plus** the DB-backed runtime trusted networks), and delegates to the pure rule engine `SecretAccessPolicy` in Core (fully unit-testable, no framework types — see the `EclipsVault.Tests` decision matrix). Denials surface their exact reasons on the Denied page.
- **Fail-closed audit** — an EF `SaveChangesInterceptor` injects an `AuditLogs` row into the *same transaction* as every secret insert/update/delete; if the audit can't be written the whole transaction rolls back. Reads are audited *before* decryption — no audit row, no plaintext, and the caller gets a 503, never data.
- **Tamper-evident audit trail** — the same interceptor is the single choke point for every audit insert, so it stamps each row into a **hash chain**: `EntryHash = SHA-256(row content ‖ previous row's hash)`, with a monotonic sequence. Any edit, deletion, insertion, or reorder — even by someone with direct database access — breaks the chain and is caught by the **Verify integrity** action on the Audit page, which pinpoints the exact broken entry. The chain head advances only on commit (a rolled-back write leaves no gap), it is seeded from the persisted tail on restart, and the whole pre-existing history is back-filled into the chain at first startup. Aligns with PCI-DSS 10.5, NIST 800-53 AU-9/AU-10, and SOC 2 CC7.
- **Signed audit checkpoints & external verification** — the hash chain is tamper-evident to anyone with the database; a signed checkpoint makes it tamper-evident to anyone with the *public key*. The admin Audit page can **sign** the current chain head (ECDSA P-256 / SHA-256 over the head sequence + hash) and **export** a self-contained bundle — every chained row, the signed checkpoint, and the public key. The standalone `EclipsVault.AuditVerifier` tool re-walks the chain and checks the signature *offline*, with no access to the vault, its database, or its private key — so an outside auditor can prove the trail was not rewritten even by an insider who deleted rows and recomputed every hash (they cannot forge the signature). The private key comes from `ECLIPSVAULT_AUDIT_SIGNING_KEY` (dev uses an ephemeral key). Extends the RFC 6962-style transparency model to the vault's own log.
- **Honey-tokens** — seeded decoys (`Production_AWS_Root_Key`, `Global_SQL_SA_Password`). Any by-id read bypasses ABAC entirely and: revokes the caller's sessions (server-side kill switch checked on every request), blacklists the source IP range (/24 v4, /64 v6) in middleware, writes a critical audit row, and emits a `Fatal` Serilog alert. The attacker just sees a sign-out. TopSecret administrators see a `decoy` badge and a confirm-gated open on the list so they don't trip their own trap; ordinary users see decoys as indistinguishable from real secrets.
- **Break-glass recovery** — the block page carries a *Recover access* link to `/Account/Recover`, the one path the IP-blacklist middleware exempts. It demands all factors at once (password + TOTP), is restricted to TopSecret clearance, is rate limited, and audits every attempt (`BreakGlassRecovery`). A verified admin lifts the block on their own range and is signed straight back in; anyone else is refused and the block stands. This means a locked-out administrator always has a way back to the dashboard, without a process restart.
- **TTL shredder** — a `BackgroundService` sweeps every 60 s, destroys expired key material (row remains as an auditable tombstone), evicts cache entries and logs the event. A 5-minute demo secret is seeded so you can watch it happen.
- **Caching** — cache-aside via `IMemoryCache`, 5-minute absolute TTL, *encrypted envelopes only* (never plaintext), eagerly evicted on every write/update/delete.
- **Transport & headers** — a **strict Content-Security-Policy** (`default-src 'self'`, no `unsafe-inline`; `object-src`/`frame-src`/`frame-ancestors 'none'`; `connect-src`/`form-action`/`base-uri 'self'`), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, Permissions-Policy, **COOP + CORP `same-origin`**, and `X-Permitted-Cross-Domain-Policies: none` on every response; **HSTS outside dev** with a credentials-grade policy (1-year max-age, `includeSubDomains`, and `preload`, rather than the framework's 30-day default); **`Cache-Control: no-store` on every HTML response** (so authenticated vault pages are never written to the browser's disk cache or served from the back button after sign-out, while static assets and images keep their own caching); `SameSite=Strict` + `HttpOnly` + `Secure` on all cookies; global `AutoValidateAntiforgeryToken`; per-IP fixed-window rate limiting on the auth surface (returns `429`); default-deny fallback authorization policy; no `Server` header. Because the CSP forbids inline scripts and styles, **all** interaction is wired through `site.js` data-attributes (no inline `onclick`/`style` anywhere) — a CSP-clean pattern rather than a `'unsafe-inline'` escape hatch.
- **Session management & revocation** — an interactive session is issued a random id at sign-in that travels in the cookie. A server-side **session registry** (runtime state, in-process on one node / Redis-backed across a cluster, like the other shared-state stores) tracks each live session and holds a tombstone for revoked ones; the cookie's `OnValidatePrincipal` checks **both** the account-wide kill switch (revoke everything issued before an instant — used by "sign out everywhere", role/enable changes, and the intrusion response) **and** the per-session tombstone, so a single "signed-in device" can be signed out on its own and is rejected on its next request, on every node. Last-seen is refreshed as best-effort metadata (throttled, never able to fail a valid session), and every self-service revoke is audited.
- **Real client IP behind a proxy** — `ForwardedHeaders` middleware recovers the true caller address from `X-Forwarded-For`, but **only from proxies you list** in `ForwardedHeaders:KnownProxies` (with none listed, the socket address is used — safe for direct exposure). Every IP-based control — the rate limiter, the intrusion IP-blacklist, the ABAC trusted-network check, and the audit `SourceIp` — depends on this being correct, so it must be configured whenever the app runs behind a load balancer or ingress.

## Extension points

- **Cloud KMS** — implement `ICryptoEngine`, register it in `CryptoEngineFactory`, set `Crypto:Engine`. The `VaultTransit` engine is the reference implementation; an AWS KMS or Azure Key Vault engine follows the same shape (wrap/unwrap the DEK via the provider's SDK).
- **Passkey relying party** — the WebAuthn ceremonies live behind the Core `IPasskeyService` port (implemented in `Infrastructure/Security/WebAuthn`); a managed FIDO2 service could replace the built-in verifier without touching the domain, controllers, or views.
- **Multi-node** — set `Redis:Enabled=true` to back the IP blacklist, session revocation, and envelope cache with Redis (see [Horizontal scale-out](#horizontal-scale-out-redis)); the `Redis*`/`InMemory*` pairs implement the same Core interfaces, so adding another distributed store (e.g. the rate-limiter partition) is the same swap.
- **Migrations** — schema is managed by EF Core Migrations (`Infrastructure/Migrations/`), applied at startup via `MigrateAsync()`. The existing dev database was baselined onto the initial migration, so no data was lost in the switch-over.

## Proposed roadmap

Shipped so far — both built on the existing seams and each verified end-to-end:

- ✅ **Account lockout** — 5 failed password/TOTP attempts lock the account (`FailedAccessCount`/`LockedUntilUtc` on `User`, enforced in `VaultAuthenticationService`), with an admin **Unlock**. Complements the per-IP rate limiter.
- ✅ **Secret rotation & version history** — prior values kept as envelope-encrypted `SecretVersion` rows; timeline with reveal/revert. First feature delivered through the EF-migration workflow (`AddSecretVersioning`).

- ✅ **Login by username or email + auto-generated unique emails** — `first.last.N@domain`, N per name; email is a unique login identity. Migration `AddUniqueEmailIndex`.
- ✅ **Expiry notifications** — dashboard banner + "Expiring soon" panel with countdowns and Rotate links, over the existing lifecycle/dashboard infra.

- ✅ **Secret sharing / access grants** — per-user grants (optional expiry) that satisfy the ABAC project rule only; "Shared with me" sidebar page; audited; cascade-deletes. Migration `AddSecretGrants`.

- ✅ **Service accounts & scoped API keys** — non-interactive identities with SHA-256-hashed keys and their own ABAC attributes; `/api/v1/secrets` for programmatic retrieval, governed by the same policy. Migration `AddServiceAccounts`.

- ✅ **Passkeys / WebAuthn** — passwordless MFA: register authenticators from the profile and sign in with no password or TOTP. A self-contained relying-party verifier (CBOR/COSE + BCL crypto, ES256/RS256) behind the `IPasskeyService` port; user-verification required; challenge held server-side; signature-counter clone detection; every ceremony audited. No schema change — the `PasskeyCredentials` table shipped in `InitialCreate`.

- ✅ **Light/dark theme toggle** — the design system is tokenised, so the light theme is a single `:root[data-theme="light"]` token block (surfaces invert to layered whites, hairlines become black-alpha, the amber accent deepens to stay readable). The choice persists in an `EclipsVault.Theme` cookie the server reads to stamp `data-theme` on `<html>`, so the first paint is already correct (no flash) — CSP-safe, no inline script. A sidebar toggle flips it live.

- ✅ **Per-key API scopes** — a key can be issued narrower than its service account: a clearance ceiling, a single permitted project (binding even a TopSecret account), and/or metadata-only. Scope travels as claims and is enforced as extra deny-rules in the same pure ABAC engine, so a scoped key can only ever see a subset of the account. Issue-time UI in the Service accounts console; each key's scope is shown on its row and recorded in its issue audit. Migration `AddApiKeyScopes`.

- ✅ **Secret access requests** — the self-service loop over the existing grants system, surfaced as a new **Access requests** sidebar page. A denied secret's page offers a request form; reviewers (admins or project members) approve (creating a grant) or reject from a queue; approval is governed by the same ABAC engine (a grant only fixes a project denial). Denial reasons are snapshotted for the reviewer, every transition is audited, and requests cascade-delete with the secret. Migration `AddAccessRequests`.

- ✅ **Notifications / email delivery** — a pluggable `IEmailSender` transport (SMTP for prod, a dev Log transport, chosen by `Email:Sender`) with a fail-soft `INotificationService` that composes messages for domain events (access-request decisions, password changes, user provisioning) and records every one to an **outbox**, viewable on a new admin **Notifications** sidebar page. Migration `AddEmailLog`.

- ✅ **Tamper-evident audit log** — hash-chained audit trail (each row commits to the previous), with an admin **Verify integrity** action that detects and pinpoints any modification, deletion, or reorder. Pre-existing history is back-filled into the chain at startup. Migration `AddAuditChain`. Maps to PCI-DSS 10.5, NIST 800-53 AU-9/AU-10, SOC 2 CC7. *(Security-standards hardening track.)*

- ✅ **KEK rotation & key lifecycle** — a multi-KEK provider (current + retired keys, resolvable by id) and an admin **Encryption keys** page that re-wraps every secret's DEK under the current KEK — payload ciphertext untouched, shredded tombstones skipped, every rotation audited (`KekRotated`). No schema change (the `KekId` seam already existed). NIST 800-57, PCI-DSS 3.6/3.7. *(Security-standards hardening track.)*

- ✅ **MFA recovery codes** — single-use backup codes, generated from the profile and shown once, that redeem in place of TOTP when the authenticator is lost. Stored only as salted Argon2id hashes; verified without an early-out timing signal; consumed on use; wired into lockout and the audit trail; and purged whenever the authenticator is reset. Migration `AddMfaRecoveryCodes`. NIST 800-63B "look-up secrets". *(Security-standards hardening track.)*

- ✅ **Breached-password screening** — every password set or changed is refused if it appears in a bundled, offline compromised-password corpus (embedded resource, loaded once into a case-folded `HashSet`), with a debounced live check on the change-password / create-user forms. Behind the `IBreachedPasswordScreen` port. NIST 800-63B §5.1.1.2, OWASP ASVS 2.1.7. *(Security-standards hardening track — this completes the track.)*

- ✅ **Signed audit checkpoints & offline verification** — the hash-chained audit trail can now be signed (ECDSA P-256) at its head and exported as a self-contained bundle, verifiable *offline* by the new standalone `EclipsVault.AuditVerifier` project with no access to the app, its database, or its private key. This lifts tamper-evidence from "provable to anyone with the DB" to "provable to anyone with the public key," defeating even an insider who rewrites the whole chain. Migration `AddAuditCheckpoints`; new `Infrastructure/Auditing` + reorganised `Infrastructure/Security` (Cryptography/ · Defense/ · WebAuthn/). RFC 6962-style transparency; NIST 800-53 AU-9.

- ✅ **API-key network binding (IP allow-listing)** — a service-account key can be pinned to source CIDR ranges; presented from anywhere else it is rejected at authentication (`401`). Enforced against the real client IP, so a leaked key is useless off-network. Migration `AddApiKeyIpAllowlist`. Shipped alongside an architecture cleanup: all IP/CIDR logic (address normalisation, range matching, block-range derivation) consolidated from three duplicated copies (Web + two Infra services) into one canonical `NetworkRules` in Core, now reused by ABAC, the trusted-network store, the intrusion blacklist, and key binding.

- ✅ **Step-up re-authentication for sensitive reveals** — revealing a Secret/TopSecret value with a stale session forces a fresh authenticator code, entered inline on the secret's own page, before decryption. The decision is a pure Core rule (`IStepUpService.IsRequired`) driven by `StepUp:MinimumSensitivity` / `MaxAuthAgeMinutes`; a successful step-up refreshes a strong-auth claim so the window reopens briefly; both outcomes are audited. New `Application/StepUp` feature slice, no schema change. NIST 800-63B §4.2.3.

**Engineering hardening** (from a security & architecture review — all landed):

- ✅ **Secrets out of source** — the DB connection string left `appsettings.json`; it now comes from the environment/secret store (dev value in git-ignored `appsettings.Development.json`). Least-privilege login + `Encrypt=True` for real deployments.
- ✅ **Correct client IP behind a proxy** — `ForwardedHeaders` with an explicit known-proxy allowlist, so rate limiting, the IP-blacklist, ABAC trusted-network, and audit `SourceIp` stay accurate behind a load balancer.
- ✅ **Test suite + CI** — `EclipsVault.Tests` (xUnit) covering the ABAC matrix, audit hash-chain, recovery-code format, and crypto round-trip; a GitHub Actions pipeline that builds, tests, and audits dependencies. It immediately caught a latent bug (the rate limiter set a non-existent HTTP 430 instead of 429).
- ✅ **Reproducible builds** — central package management with pinned versions + committed lockfiles; warnings-as-errors quality gate.
- ✅ **Timezone-aware access window**, throttled API-key last-used writes, and a shared audit-writer extension (dedupe).
- ✅ **Distributed state for horizontal scale-out (Redis)** — the three pieces of shared runtime state (session revocation, the intrusion IP blacklist, the encrypted-envelope cache) can now live in **Redis** behind their existing Core interfaces, so the app runs as multiple replicas: a revocation or block on one node is enforced on all, and a write evicts the cached envelope everywhere. The async interfaces are backed by either `Redis*` or `InMemory*` implementations selected by `Redis:Enabled`; the blacklist keys each block by its canonical range so the hot-path check stays a single O(1) lookup. Verified end-to-end against a real Redis, including a revoked cookie staying dead across a full app restart. See [Horizontal scale-out](#horizontal-scale-out-redis).

**Toward production — bigger initiatives** (need infrastructure or are multi-week features, best sequenced one at a time):

- **Remaining HA state** — the last two pieces of single-node state: move the auth **rate-limiter** partitions to a Redis-backed store (the built-in `System.Threading.RateLimiting` partitions are per-process), and give the audit hash-chain a **DB-side sequence** so concurrent writers on different replicas can't race the chain head. The three security/cache stores above are already distributed.
- ✅ **KMS-backed KEK (HashiCorp Vault Transit)** — the master key can now live in Vault instead of an environment variable: the `VaultTransit` crypto engine wraps/unwraps each DEK via Vault's Transit API, so the KEK never enters process memory. Opt-in via `Crypto:Engine=VaultTransit`; verified end-to-end against a local dev Vault (a secret created and revealed through the app, stored with `KekId=vault:eclipsvault:v1` and a `vault:v1:` wrapped DEK). An AWS KMS / Azure Key Vault engine would follow the same `ICryptoEngine` shape (needs the respective cloud credentials).
- **Dynamic secrets & leasing** — issue short-lived, auto-revoked backend credentials on demand (the flagship capability of a Vault-class engine), and rotate the *actual* upstream secret, not just re-wrap the DEK.
- **SSO (OIDC/SAML) + SCIM** — enterprise identity, with clearance/project attributes flowing from the IdP.
- **Further clean-arch** — move `TrustedNetworkService` / `IntrusionResponseService` off `DbContext` and behind Core repository ports; wire near-TTL secrets through the notification service.

## Notes

- List views show metadata only and are not per-row audited; every by-id metadata view and every reveal is audited (`SecretMetadataViewed`, `SecretRevealed`).
- Honey-token blacklisting defaults to process-local (in-memory); tripping it from localhost blocks you until app restart — that's the feature working. With `Redis:Enabled=true` the block instead persists in Redis (and across restarts) and is shared by every node — lift it from the **Networks** console or via break-glass recovery.
- The seeded `Seed:AdminPassword` / `Seed:DevPassword` values live only in `appsettings.Development.json`; change them, or remove the section and set them via user-secrets/environment.
