# Small local evaluation lab

One PostgreSQL database and Mailpit, bound to loopback. This setup uses cached images and a 256 MiB
RAM filesystem for the database: **no database disk volume and no backups**. Stopping or recreating
the database discards its data, including enrolled MFA accounts. It is for invented values only.
The application runs on the host, so this setup does not build another application image.

## Start the dependencies

From this checkout, initialise once with the path of your patched candidate:

```bash
python3 evaluation/prepare.py /path/to/patched-candidate
docker compose -f evaluation/compose.yml --env-file evaluation/.env config --quiet
docker compose -f evaluation/compose.yml --env-file evaluation/.env up -d --wait
```

The initializer refuses to overwrite an existing development configuration or lab credentials.
Generated settings and login details are private, gitignored files. Open
`evaluation/.local/credentials.txt` locally for the `vault-admin` and `dev-user` passwords; do not
paste them into chat. The database is at `127.0.0.1:55432`; the mail viewer is
<http://127.0.0.1:18025>. No SMTP account or real email credentials are needed.

The image digests are pinned to images already cached on the maintainer's machine. `pull_policy:
never` makes a missing image fail rather than downloading it. Another machine must install those
digests explicitly before using this lab.

## Build and run the candidate once its vendor licence is accepted

In the **candidate checkout**, complete the [candidate gate](../docs/COMMUNITY_EVALUATION_SETUP.md#candidate-gate).
The downloaded ImageSharp vendor licence currently fails build validation; vendor confirmation is
pending. Starting these containers does not resolve that prerequisite. Only after restore, the
Release build and tests pass, run:

```bash
dotnet dev-certs https --trust
dotnet run --project EclipsVault.Web -c Release --no-build --launch-profile https
```

Open <https://localhost:7443>. Sign in as `vault-admin` and enroll MFA; create a fresh Standard,
PHOENIX test user and the fixtures from [evaluation preparation](../docs/COMMUNITY_EVALUATION_SETUP.md).
Run [T1–T7](../docs/COMMUNITY_WALKTHROUGH.md) and record the results in the
[feedback template](../docs/COMMUNITY_FEEDBACK.md). For an application restart check, stop only the
`dotnet run` process and run it again while PostgreSQL stays running; verify the dummy value and MFA
still work. The audit signing key is ephemeral in this Development lab, so signing-key continuity
across application restarts is not assessed.

## Stop and discard the session

Stop the application with Ctrl+C, then run from this lab checkout:

```bash
docker compose -f evaluation/compose.yml --env-file evaluation/.env down
```

This removes only the lab's containers and network. It discards the RAM database and captured emails;
cached images and the small local settings/key-ring files remain for reuse. The next start creates a
fresh database and requires MFA enrollment again. No backup or restore rehearsal is performed here.
Old authenticator codes belong to the discarded enrollment; enroll again on the new database.
Retire the old authenticator entry once you have confirmed which entry belongs to the new session.
Avoid Docker-wide prune commands: unrelated projects may share the cached images.
