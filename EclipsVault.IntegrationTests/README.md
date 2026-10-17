# Release HTTP regression tests

This small harness targets the v1.4.0 MVC application. It does not need the unreleased Angular or
Foundation UI API. Docker must be running (SQL Server uses Linux amd64, including emulation on an
ARM host). The SQL Server image is pinned by digest in `VaultFixture`.

```sh
dotnet restore --locked-mode
dotnet build EclipsVault.slnx -c Release --no-restore
dotnet test EclipsVault.Tests -c Release --no-build --blame-hang-timeout 5m --blame-hang-dump-type mini
dotnet test EclipsVault.IntegrationTests -c Release --no-build --blame-hang-timeout 10m --blame-hang-dump-type mini
dotnet list package --vulnerable --include-transitive
```

The fixture starts the real app in Production over loopback HTTPS sockets. Its client trusts only
its own disposable certificate. It configures loopback as a trusted reverse proxy and assigns test
clients distinct forwarded source addresses; the real authentication throttle and ABAC rules run.
It generates disposable passwords, KEK, audit-signing key and an encrypted persisted Data Protection
ring. No existing key or credential file is read. Password sign-in and real TOTP enrollment establish
each cookie. Antiforgery remains enabled, with a missing-token negative control.

Separate cases cover immediate replay and replay on a fresh host with the same SQL database, KEK
and persisted key ring, and new in-memory revocation services. A surviving account's retained cookie
and form token must still Reveal the same disposable secret on the fresh host. The deleted account's
original and copied cookies must be refused, with no plaintext returned. Assertions and test output
never print passwords, keys, cookies, tokens or the disposable plaintext.

A disabled-account case also checks fresh-host refusal. The avatar HTTP case uploads real JPEG/PNG
forms and checks that malformed, truncated, oversized-dimension and oversized-body uploads leave
the previously stored valid PNG unchanged.

Testcontainers disposes only its own named SQL container and helper resources. The fixture removes
its own temporary key ring and restores environment variables. It does not delete pre-existing
containers, images or volumes. A hang timeout abort is a failed run, not a passing test.
