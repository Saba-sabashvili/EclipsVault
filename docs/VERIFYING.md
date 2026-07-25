# Verifying a release

Every EclipsVault release image is **cryptographically signed** so you can prove the image you are
about to run was built by this project's release pipeline and has not been tampered with in transit or
in the registry. For a product that holds your credentials, verifying the binary before you run it is
worth the two commands below.

## How the signing works

Signing is **keyless**, using [Sigstore](https://www.sigstore.dev/) `cosign`:

- There is **no long-lived signing key** to leak. Each release is signed by the GitHub Actions release
  workflow's own identity (via OpenID Connect), using a short-lived certificate.
- The signature is recorded in the public **Rekor transparency log**, so it is independently auditable
  and cannot be produced retroactively without a public record.
- You verify against the **workflow identity**, so a valid signature can only have come from this
  repository's `release.yml` pipeline — not from anyone who merely obtained a key.

The image is published to the GitHub Container Registry:

```
ghcr.io/saba-sabashvili/eclipsvault
```

## 1. Install cosign

See the [cosign install guide](https://docs.sigstore.dev/cosign/system_config/installation/). On most
systems:

```bash
# macOS
brew install cosign

# Linux (or verify the checksum from the cosign release page)
curl -sSfL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 \
  -o cosign && chmod +x cosign && sudo mv cosign /usr/local/bin/
```

## 2. Verify the image signature

Replace `1.0.0` with the release you intend to run. Note that **image tags carry no `v` prefix**: the
git tag `v1.0.0` publishes the image as `:1.0.0` (plus a rolling `:1.0` for the minor series).

```bash
cosign verify \
  --certificate-identity-regexp \
    'https://github.com/Saba-sabashvili/EclipsVault/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer \
    'https://token.actions.githubusercontent.com' \
  ghcr.io/saba-sabashvili/eclipsvault:1.0.0
```

A successful verification prints the checked claims and exits `0`. It confirms the image was signed by
this repository's release workflow. **If it fails, do not run the image** — the signature is missing,
does not match, or the image is not what the pipeline produced.

## 3. (Recommended) Pin to the digest you verified

Tags are mutable; a digest is not. Once verified, resolve and run the image by its `sha256` digest so
you always run the exact bytes you checked:

```bash
digest=$(cosign verify \
  --certificate-identity-regexp \
    'https://github.com/Saba-sabashvili/EclipsVault/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer \
    'https://token.actions.githubusercontent.com' \
  ghcr.io/saba-sabashvili/eclipsvault:1.0.0 2>/dev/null \
  | jq -r '.[0].critical.image."docker-manifest-digest"')

echo "Verified digest: $digest"
docker pull "ghcr.io/saba-sabashvili/eclipsvault@${digest}"
```

Use `ghcr.io/saba-sabashvili/eclipsvault@${digest}` wherever `docs/INSTALL.md` shows the image name.

## 4. (Optional) Verify and read the SBOM

Each release also ships a **signed CycloneDX SBOM** attached to the image as an attestation, so you can
audit exactly what ships in the version you run:

```bash
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp \
    'https://github.com/Saba-sabashvili/EclipsVault/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer \
    'https://token.actions.githubusercontent.com' \
  ghcr.io/saba-sabashvili/eclipsvault:1.0.0 \
  | jq -r '.payload | @base64d | fromjson | .predicate' > sbom.json
```

`sbom.json` now holds the verified bill of materials for that image.

## What verification does and does not prove

- **Proves:** the image was produced by this repository's release workflow and has not been altered
  since. The bill of materials is authentic.
- **Does not prove** anything about *your* deployment's security — that remains yours, per
  [`THREAT_MODEL.md`](THREAT_MODEL.md). Verifying the image is one link in the chain, not the whole one.
