# Installing your licence

Your Max licence arrives as a **single line of text** — a signed token beginning `EVLIC1.`. That line
is the whole licence. There is nothing to activate, no server to reach, and no account to create.

Verification happens entirely inside your deployment, against a public key compiled into the build.
The vault never contacts us, and it does not need outbound internet access to be licensed. If your
vault sits in an air-gapped network, everything below still works.

---

## The file

Save the token as a `.lic` file, one line, no trailing spaces:

```
eclipsvault-<your-org>-<licence-id>.lic
```

For example `eclipsvault-acme-3f9c1b7a2e04.lic`. The licence id is printed on your invoice and is the
value shown on the vault's **Licence** page, so matching filenames to invoices makes renewals and
support unambiguous. The name has no technical meaning — only the contents matter.

Treat the file the way you would treat a licence key, not a credential: it identifies your entitlement
and it is signed, so it cannot be altered without invalidating it. It contains no secret of yours.

---

## Installing it: two ways

Pick whichever fits how you deploy. The environment variable takes precedence when both are present.

### 1. Environment variable (simplest)

```bash
ECLIPSVAULT_LICENSE="EVLIC1.eyJ...<the rest of the token>"
```

Docker Compose:

```yaml
services:
  eclipsvault:
    image: ghcr.io/saba-sabashvili/eclipsvault:1.1.0
    environment:
      ECLIPSVAULT_LICENSE: "EVLIC1.eyJ..."
```

### 2. Mounted file (better for Kubernetes and secret managers)

Point the vault at a file containing the token:

```yaml
environment:
  License__FilePath: /etc/eclipsvault/licence.lic
volumes:
  - ./eclipsvault-acme-3f9c1b7a2e04.lic:/etc/eclipsvault/licence.lic:ro
```

Kubernetes, mounting from a Secret:

```yaml
env:
  - name: License__FilePath
    value: /etc/eclipsvault/licence.lic
volumeMounts:
  - name: licence
    mountPath: /etc/eclipsvault
    readOnly: true
volumes:
  - name: licence
    secret:
      secretName: eclipsvault-licence
```

```bash
kubectl create secret generic eclipsvault-licence \
  --from-file=licence.lic=./eclipsvault-acme-3f9c1b7a2e04.lic
```

---

## Confirming it took

Restart the vault and open **Admin → Licence**. A licence that has been read correctly shows the
organisation it was issued to, the tier, the licence id, and the update window.

The startup log also records the outcome, and the result is written to the audit trail — so "when did
this deployment become licensed" is an auditable fact rather than a memory.

---

## If something is wrong

**Nothing stops.** Enforcement is soft by design and this is not a disclaimer — it is the deliberate
behaviour, tested and documented. A missing, malformed, expired, or unrecognised licence produces an
administrator banner and an audit entry. It never disables a feature, never blocks decryption, and
never prevents the vault serving a secret. A security tool that outages over a licence check is not a
security tool.

So if the banner says you are unlicensed, your vault is still working. You have time to sort it out.

| What you see | What it means |
|---|---|
| *No licence is configured* | The variable or file was not found. Check the name: `ECLIPSVAULT_LICENSE`, or `License__FilePath` pointing at a readable path. |
| *Not a readable EclipsVault token* | The text was truncated, wrapped, or had characters inserted. Re-copy it as one unbroken line — mail clients and chat apps are the usual culprits. |
| *Signature is not valid for this build* | The licence was not signed for this build's vendor key. Most often the build predates your licence — see below. Send us the licence id and the version you are running. |
| *Expired* | Only evaluation licences expire. A purchased Max licence is perpetual and never reaches this state. |

**A note on older builds.** The vendor's public key is compiled into each release. A licence can only
verify on a build whose pinned key matches the key it was signed with, so a release published *before*
your licence was issued may not accept it. If you hit this, upgrade to the version named on your
invoice. We will always tell you the minimum version your licence requires.

---

## Perpetual, and what the update window means

A Max licence is **perpetual**. It grants its features forever; there is no renewal that keeps your
vault working, because nothing ever stops working.

What has a date on it is the **update window** — twelve months, during which you are entitled to new
releases. When it lapses:

- your vault keeps running, fully licensed, indefinitely
- every feature stays exactly as it was
- you keep receiving **security patches**, free, regardless of window status
- you stop being entitled to new *feature* releases until you renew

The banner will nudge you when the window lapses. That is all it does.

---

## Renewing, replacing, or moving a licence

Email us with your licence id.

- **Renewing the update window** — we mint a replacement token with a new window. Same licence id,
  same organisation. Install it exactly as above; it supersedes the old one.
- **Lost the token** — we reissue it. It is not a secret, so this is routine.
- **Moving to different hardware** — nothing to do. The licence is not bound to a machine, and there
  is no activation to release. Move it.
- **Another production instance** — Max is licensed per production deployment, so a second production
  environment needs a second licence. Replica count and user count are unlimited within one deployment.

---

## What this licence does not do

Stated plainly, because a licence page that only lists what you get is not much use:

- It does **not** phone home, at install time or ever. There is no usage reporting.
- It does **not** bind to your hardware, and it cannot be revoked remotely. Once you hold a token, it
  works. A refund is a commercial matter settled between us, not a technical shutdown.
- It does **not** gate security. Every baseline protection is identical in Community and Max.

Questions: **sabasabashvili86@gmail.com**, quoting your licence id.
