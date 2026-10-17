---
name: release
description: Cut an EclipsVault release. Tag vX.Y.Z on main, let release.yml build, sign and attest the image, verify it as an anonymous user, then publish the GitHub Release. Use only when the owner asks to release a specific version.
disable-model-invocation: true
argument-hint: "Version to release, e.g. 1.5.0"
---

A release cannot be taken back. The tag publishes a public image, and its signature goes into the
public Rekor transparency log, which is permanent. Stop at the first step that fails and report it.

## 1. Preconditions

- The owner named this exact version in this session.
- You are on `main`, the working tree is clean, and `main` matches `origin/main` after `git fetch origin`.
- CI passed on that commit. Check the conclusion with `gh run list --branch main --limit 5`, and
  `gh run view <id>` if needed. A log tail is not evidence.
- The version is valid semver and higher than `git tag --sort=-v:refname | head -1`.

## 2. Release notes

Draft the annotated tag message from `git log <previous-tag>..HEAD --oneline`. Match the existing
style (`git tag -n20 <previous-tag>`): a first line `EclipsVault X.Y.Z`, then one short paragraph per
change a user would notice. Show the draft to the owner and wait for approval.

## 3. Tag and push

```bash
git tag -a vX.Y.Z -F <notes-file>
git push origin vX.Y.Z
```

## 4. Watch the release workflow

`gh run list --workflow release.yml --limit 1`, then `gh run watch <id> --exit-status`. Confirm with
`gh run view <id>` that the conclusion is `success`, and note the image digest from the build step.

## 5. Verify as an anonymous user

Image tags have no `v`: git tag `v1.5.0` publishes `ghcr.io/sabysabashvily/eclipsvault:1.5.0`, plus
`:1.5` and `:latest` for a normal release. A prerelease gets only its full version tag.

```bash
TOKEN=$(curl -s "https://ghcr.io/token?scope=repository:sabysabashvily/eclipsvault:pull" | jq -r .token)
ACCEPT='application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json'
for ref in X.Y.Z X.Y latest sha256-<digest-hex>.sig sha256-<digest-hex>.att; do
  printf '%s ' "$ref"
  curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" -H "Accept: $ACCEPT" \
    "https://ghcr.io/v2/sabysabashvily/eclipsvault/manifests/$ref"
done
```

Every line must print `200`. The `.sig` and `.att` tags hold the signature and the SBOM attestation;
an image whose signature cannot be fetched fails `cosign verify` even though the image itself pulls.
If `cosign` is installed, set `VERSION` to the released version and use the current-owner `IDENTITY`
from `docs/VERIFYING.md`, then run its `cosign verify` command.

## 6. Publish the GitHub Release

```bash
gh release create vX.Y.Z --verify-tag --title "EclipsVault X.Y.Z" --notes-from-tag --latest
```

Use `--prerelease` instead of `--latest` for a prerelease. Without this step the repository keeps
showing the previous version as Latest, even though the new image is live.

## 7. Report

The version, the image digest, the HTTP result for each tag, and the release URL.
