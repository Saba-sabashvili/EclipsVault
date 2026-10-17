---
name: run-vault
description: Run EclipsVault locally and sign in to it. Start the vault on 7443, get a real session for curl or the browser preview, make a throwaway account. Use when verifying a change in the running app.
---

Local connection details live in `EclipsVault.Web/appsettings.Development.json` (never committed):
the SQL password is in `ConnectionStrings:DefaultConnection`, and `dev-user`'s password is
`Seed:DevPassword`. Pass them through environment variables; never print them or write them into a file.

## 1. Database

`docker compose up -d` starts SQL Server as `eclipsvault-db`; a machine may instead use its own
container (check `docker ps`). Start Docker Desktop first if needed (`open -a Docker`). Ready means
`sqlcmd` answers `SELECT 1`: an open port is not enough.

```bash
docker exec <container> /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$EV_SQL_PASSWORD" -C -d EclipsVaultUmbraDb -Q "SELECT 1"
```

## 2. Build, then start

Build with `dotnet build EclipsVault.slnx -c Release`. Any path the Angular UI owns also needs
`npm run build` in `EclipsVault.AngularUi`, or it answers with the error page.

Start the built dll from `EclipsVault.Web` (the content root), self-limiting so it cannot outlive the session:

```bash
cd EclipsVault.Web && (ASPNETCORE_ENVIRONMENT=Development ASPNETCORE_URLS="https://localhost:7443;http://localhost:5080" \
  perl -e 'alarm shift; exec @ARGV' 3600 dotnet bin/Release/net10.0/EclipsVault.Web.dll > /tmp/vault.log 2>&1 &)
```

macOS has no `timeout`, hence `perl`. Running the dll rather than `dotnet run` matters: `dotnet run`
starts the app as a child process that survives when the parent is killed. Ready when
`curl -sk -o /dev/null https://localhost:7443/` succeeds; stop with `pkill -f EclipsVault.Web.dll`.

## 3. An account

`dev-user` is seeded (Standard clearance, project PHOENIX). For any other clearance, clone it, so
the clone shares its password and authenticator secret. Clearance is 1 (Standard) to 4 (Top Secret):

```sql
INSERT INTO Users (Id,Username,Email,PasswordHash,PasswordSalt,TotpSecret,TotpEnabled,Clearance,ProjectKey,CreatedAtUtc,DisplayName,IsDisabled,AvatarUpdatedAtUtc,FailedAccessCount,LockedUntilUtc,LastTotpStep)
SELECT NEWID(),'agent-admin','agent-admin@example.invalid',PasswordHash,PasswordSalt,TotpSecret,1,4,'GLOBAL',SYSDATETIMEOFFSET(),'Agent Admin',0,NULL,0,NULL,NULL FROM Users WHERE Username='dev-user'
```

Delete the clone when done: `DELETE FROM Users WHERE Username='agent-admin'`.

## 4. Sign in

For curl, `signin.py` (next to this file) runs the real sign-in, password then a real TOTP code, and
writes a cookie jar:

```bash
EV_PASSWORD=… EV_SQL_PASSWORD=… EV_SQL_CONTAINER=<container> python3 -I .claude/skills/run-vault/signin.py dev-user /tmp/vault.jar
curl -sk -b /tmp/vault.jar https://localhost:7443/api/ui/me
```

In the browser preview, compute the code the same way the script does. Click each field before
`preview_type` (with `clear: true`) and confirm the values with `preview_evaluate` before submitting:
typing into a page still loading submits an empty form. Read page text with `preview_evaluate`
(`document.body.innerText`); `preview_snapshot` returns the whole network and action log on every
call, so take one at the end for its `consoleEntries`, where CSP violations appear as errors.

The sign-in budget:
- **Throttle:** 11 sign-in POSTs per 120 s per IP, and a sign-in spends 2. Restarting the vault
  clears it in Development.
- **One code per step:** an authenticator code works once per account per 30-second step. Two
  sign-ins as the same account (curl, then browser) need a new step between them.
- **Return URL:** the sign-in drops `ReturnUrl` at the TOTP step and lands on `/Secrets`, so
  navigate to the page under test afterwards.
