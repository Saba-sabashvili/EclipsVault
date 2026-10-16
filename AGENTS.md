# EclipsVault: instructions for coding agents

Self-hosted secrets manager. ASP.NET Core MVC on .NET 10, Clean Architecture: Web → Infrastructure → Core.
Core references only the BCL: no NuGet packages, so no `ILogger` and no `IMemoryCache` there.

## Build and test

- The solution file is `EclipsVault.slnx`. There is no `.sln`.
- Restore: `dotnet restore --locked-mode`. It fails when a `packages.lock.json` is stale; regenerate the
  lock files whenever you change `Directory.Packages.props`.
- Build: `dotnet build EclipsVault.slnx -c Release`. Warnings, including analyzer findings, fail the build.
- Test (unit, no Docker): `dotnet test EclipsVault.Tests -c Release --no-build --blame-hang-timeout 5m --blame-hang-dump-type mini`
- Integration tests: `dotnet test EclipsVault.IntegrationTests -c Release --no-build --blame-hang-timeout 10m --blame-hang-dump-type mini`.
  They need Docker running: each run starts SQL Server with Testcontainers and boots the unmodified
  `Program` against it in Production, signing in through the real sign-in. The image is pinned by
  digest in `VaultFixture`, and a machine without it downloads about 2.5 GB on the first run.
  `dotnet test EclipsVault.slnx` runs both suites, so it needs Docker too.
- A model change needs a migration in both sets: SQL Server (`EclipsVault.Infrastructure`) and PostgreSQL
  (`EclipsVault.Migrations.Postgres`). CI checks both; the exact `dotnet ef` commands are in
  `.github/workflows/ci.yml`. For Postgres the startup project is `EclipsVault.Web`.
- Agent guardrail tests: `python3 -I -m unittest discover -s .claude/hooks -p 'test_*.py'`.

## Known traps

- Errors in files you did not touch (RZ1021, `CS0246` naming `summary` or `button`): run
  `dotnet build-server shutdown` and rebuild before debugging code. Deleting `obj/` does not help.
- A test run that stops with "The specified inactivity time of 5 minutes has elapsed" (10 minutes for the
  integration tests) is a hang.
  The long-standing `AuditGroupCommitterTests` hang was fixed in #37, so a hang now is a regression
  to investigate, not a known flake. Test output is buffered: the last test printed is not the one
  that hung. The aborted run's blame `Sequence_*.xml` names the test still in flight.
- A newly published advisory can turn CI red with no code change. Against a direct dependency it
  fails restore and build (`NU1902`/`NU1903` are errors here). Against a transitive one, restore and
  build can still pass and only CI's `security-scan` job fails; reproduce it with
  `dotnet list package --vulnerable --include-transitive`. Either way that is the gate working:
  upgrade the package, or pin the transitive one in `Directory.Packages.props` (transitive pinning
  is on), rather than suppress the warning. Microsoft's monthly security release often triggers this.
- `dotnet test --no-build` runs whatever binaries are already in `bin/`, possibly from another
  branch. Build first, or the result proves nothing.
- Never report CI as green unless you have seen the check results yourself (`gh pr checks <n>`).

## Architecture (pinned by `EclipsVault.Tests/Architecture/LayeringTests.cs`)

- Interface in `Core/Application/<Feature>/`: the implementation lives in Core.
  Interface in `Core/Application/Abstractions/`: the implementation lives in Infrastructure.
- Web may name Infrastructure only in `Program.cs`. A controller never takes an infrastructure options
  type; add a narrow read-only port in `Core/Application/Abstractions` instead (see `ISsoAvailability`).
- One enum per file.

## Conventions

- Never construct an `AuditLog` by hand. Standalone events go through `IAuditSink.WriteAsync`
  (fail-closed). Events that must be atomic with a data change go through `AuditSaveChangesInterceptor`:
  add a `Describe<Entity>Change` rule.
- A startup audit write runs from an `IHostedService` registered after `AuditGroupCommitter`. Written
  inline before `app.Run()` it waits forever.
- Read claims through `ClaimsPrincipalExtensions` or the `VaultController` helpers, never by hand with
  `FindFirstValue`.
- IP and CIDR logic lives in `NetworkRules`. Check it before writing any parsing.
- For a marker-only write to an audited entity, set `Entry(x).Property(...).IsModified = true`.
  `DbSet.Update` marks every column modified, so the change gets audited as a real edit.

## Security invariants: never weaken these

- Auditing is fail-closed: if the audit row cannot be written, the action does not happen.
- A licence problem never stops the vault serving secrets, and licensing lookups fail open.
- A signed perpetual licence never expires into Community on date grounds.
- Viewing a page never starts a capability's evaluation window.
- Dynamic secrets never store the minted password.
- `EclipsVault.Web/appsettings.Development.json` holds the dev KEK and seed passwords and is never
  committed. CI fails if it is.
- Never read, print, or paste a private key. Pass key files to tools by path only.

## Working rules

- Do not merge pull requests, push tags, force-push, delete branches, or rewrite history unless the
  owner asks for that specific action. Before any branch deletion, prove the branch is contained in
  `main` with `git merge-base --is-ancestor`.
- In commercial and legal documents (`LICENSE`, `docs/COMMERCIAL_TERMS.md`, `docs/PRIVACY.md`, pricing),
  never fill in or change business values: prices, dates, legal-entity status, email addresses,
  response times. List what is missing and ask.
- `docs/internal/` is private and gitignored. Never copy its contents into a tracked file.
- Commit messages are one sentence describing the change in behaviour, for example
  "Refuse a mistyped mint flag instead of minting a perpetual licence".
