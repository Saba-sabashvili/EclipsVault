# #49 app-shell evidence

Baseline: `caf052f4d438831aaef227ae27207dda5536c857`, on `angular-migration`.

`GET /api/ui/me` evaluates each Area through `IAuthorizationService` using the named policy enforced
by its pages: `Session` or `AdminOnly`. Angular maps the returned keys to presentation only. The
Standard account receives 13 Areas; the administrator receives those plus seven administration
Areas. The sidebar has one extra Secrets entry (New secret) and leaves Profile to #50.

## Verification

Run on Node 24.22.0 and .NET SDK 10.0.402.

| Check | Result |
| --- | --- |
| `dotnet restore --locked-mode` | Passed |
| `dotnet build EclipsVault.slnx -c Release` | Passed, no warnings |
| .NET unit suite with the documented hang guard | 595 passed |
| Production integration suite with SQL Server and the documented hang guard | 43 passed |
| `npm run lint` (includes browser TypeScript checking and lint guard tests) | Passed |
| `npm test -- --watch=false` | 22 passed |
| `npm run test:build-checks` | 15 passed |
| `npm run build` | Passed, including runtime dependency and inline-code gates |
| `npm run check:api-types` | Passed; generated types committed |
| `npm audit --audit-level=high` | No vulnerabilities |
| `dotnet list package --vulnerable --include-transitive` | No vulnerable packages |
| Agent guardrail tests | 6 passed |
| `npm run e2e` | 3 passed; both accounts/themes, cross-UI navigation, Trusted Types and revocation |
| `npm run e2e:verify-guards` | Passed; all 8 deliberate failures detected by the shared fixture |

Browser runs reuse `E2E_IMAGE=eclipsvault:e2e-49`, image ID
`sha256:1720457d99649fbe42711061d919b7dcd3a44681bf3b8873a9e0aa59ebecd248`.
Each run creates its own throwaway production vault and SQL Server with real password/TOTP sign-in,
TLS, Secure cookies, production CSP and Trusted Types. No development seed accounts are used.

## Visual comparison

The browser compares the real Legacy and Angular navigation on the same session: section and entry
labels, ordering, URLs, SVG geometry, active entry, expanded groups, colors, typography and spacing.
It also proves that My access uses the router, Legacy links replace the document, and returning to
Angular keeps the same session without another sign-in. Standard has no administration links in
the DOM. Screenshots crop to navigation content; the command trigger and account menu belong to
#51 and #50 respectively.

The Legacy reference uses MVC's existing optional-id route `/Access/Index/legacy`, while `/Access`
and `/Access/Index` serve Angular. This compares the same active page before #52 removes its Razor
controller. The test asserts and normalizes the reference link's ambient optional id to `/Access`.
For the light Angular capture the browser applies `data-theme="light"` directly: theme boot and
switching remain in #50. Both token palettes are exercised here without adding that feature.

| Account / theme | Legacy | Angular |
| --- | --- | --- |
| Administrator / dark | ![Legacy administrator dark](administrator-dark-legacy.png) | ![Angular administrator dark](administrator-dark-angular.png) |
| Administrator / light | ![Legacy administrator light](administrator-light-legacy.png) | ![Angular administrator light](administrator-light-angular.png) |
| Standard / dark | ![Legacy Standard dark](standard-dark-legacy.png) | ![Angular Standard dark](standard-dark-angular.png) |
| Standard / light | ![Legacy Standard light](standard-light-legacy.png) | ![Angular Standard light](standard-light-angular.png) |

## Security review

Pending.

## Standards

Pending.

## Spec

Pending.

All results above are local checks. No claim about hosted CI is made. Nothing has been pushed and
#49 remains open for the owner to review this evidence.
