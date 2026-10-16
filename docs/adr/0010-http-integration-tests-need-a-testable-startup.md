# Test the UI API over HTTP, against the app's real startup

_Originally titled "…which means making Program.cs testable". See the amendment at the end._

The UI API's guarantees can only be proven at the HTTP boundary:
- a session is refused on the Public API, and an API key on the UI API,
- an unsafe request without an antiforgery token is rejected,
- an audit failure becomes a 503 Problem Details response.

So a new integration test project hosts the app with `WebApplicationFactory`, against a real SQL Server started per run with Testcontainers.

This reverses a July 2026 decision. `WebApplicationFactory` does not currently work against this `Program.cs`: the app boots fully, then the test host is disposed before it can be used. That attempt was abandoned because finishing it needed a change to startup code. With a whole new API surface to protect, the change is now worth making: the composition and the pipeline move into methods a test host can call. Because this touches startup in a secrets vault, the `security-reviewer` agent reviews it. A real database replaces the SQLite workarounds the earlier attempt needed (SQLite cannot order by `DateTimeOffset`, which the audit chain does).

## Amended while implementing it (#43)

The restructure turned out to be unnecessary, so `Program.cs` was left unchanged. `WebApplicationFactory<Program>` boots the unmodified entry point once the vault is configured the way a container deployment configures it: through environment variables (connection string, KEK, audit signing key, key-ring path, bootstrap password, `Database__MigrateOnStartup`), in Production, against a real SQL Server. The July failure was not reproduced, and its cause was never found. The likeliest difference is what that attempt replaced to avoid a database: SQLite, a migrations assembly with nothing pending, a no-op chain locker and the removal of the hosted services.

This is stronger than the planned restructure. The test host runs the real entry point, so every test also runs the real startup tasks in their real order, and production startup code carries no seam that exists only for tests. Configuration has to reach the app as environment variables, because the composition reads parts of it while registering services, before any test-host override applies. The integration project is `EclipsVault.IntegrationTests`.
