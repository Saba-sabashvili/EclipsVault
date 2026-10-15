# Test the UI API over HTTP, which means making Program.cs testable

The UI API's guarantees can only be proven at the HTTP boundary:
- a session is refused on the Public API, and an API key on the UI API,
- an unsafe request without an antiforgery token is rejected,
- an audit failure becomes a 503 Problem Details response.

So a new integration test project hosts the app with `WebApplicationFactory`, against a real SQL Server started per run with Testcontainers.

This reverses a July 2026 decision. `WebApplicationFactory` does not currently work against this `Program.cs`: the app boots fully, then the test host is disposed before it can be used. That attempt was abandoned because finishing it needed a change to startup code. With a whole new API surface to protect, the change is now worth making: the composition and the pipeline move into methods a test host can call. Because this touches startup in a secrets vault, the `security-reviewer` agent reviews it. A real database replaces the SQLite workarounds the earlier attempt needed (SQLite cannot order by `DateTimeOffset`, which the audit chain does).
