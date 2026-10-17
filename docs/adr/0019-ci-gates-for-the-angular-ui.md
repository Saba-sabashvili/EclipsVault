# CI gates the Angular UI as strictly as the .NET code

CI gains the following, all required for migration PRs:

- **A `frontend` job:** `npm ci`, lint (including the `bypassSecurityTrust*` ban), unit tests, build, `npm audit` failing on high and critical findings, and a check that the generated UI API types match the API.
- **An `integration` job:** the Testcontainers HTTP tests (ADR-0010).
- **An `e2e` job:** Playwright against the built image with SQL Server (ADR-0011).

`security-scan` also runs the npm audit, and `sbom` adds the npm runtime packages with CycloneDX's npm tool. The existing `image` job already builds the Dockerfile, so it covers the new Node stage.
