#!/usr/bin/env bash
# Writes sbom/sbom.json: one CycloneDX bill of materials for what the image ships, the NuGet packages
# of EclipsVault.Web plus the npm runtime packages of the Angular UI it serves (ADR-0003). The release
# attests this file to the image, and CI's sbom job runs the same script on every change, so a broken
# SBOM fails a PR before it can fail a tag.
#
# A signed attestation is only as honest as the code that wrote it, so both generators are locked:
# the CycloneDX dotnet tool by the repository's dotnet-tools.json, the CycloneDX npm tool by the
# package-lock.json beside this script (audited by CI's security-scan). Nothing installed here runs
# an install script, and the release runs this in a job that can neither push nor sign.
#
# Run from the repository root. Needs: a restored solution, Node, and jq.
set -euo pipefail

dotnet tool restore
dotnet tool run dotnet-CycloneDX EclipsVault.Web/EclipsVault.Web.csproj -o sbom -fn nuget.json -F Json

# The npm half lists only the runtime packages, because they are what ships. They and the tool are
# installed into a scratch directory, which leaves the workspace's node_modules as it was. It is
# written in the NuGet half's spec version, so the merged document has one.
spec=$(jq -r .specVersion sbom/nuget.json)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/tool" "$scratch/ui"
cp .github/sbom/package.json .github/sbom/package-lock.json "$scratch/tool"
cp EclipsVault.AngularUi/package.json EclipsVault.AngularUi/package-lock.json "$scratch/ui"
(cd "$scratch/tool" && npm ci --ignore-scripts)
(cd "$scratch/ui" &&
  npm ci --ignore-scripts --omit=dev &&
  "$scratch/tool/node_modules/.bin/cyclonedx-npm" --omit dev --spec-version "$spec" --output-file ../npm.json)

# The UI becomes a component the web app depends on, and its packages and their edges join the rest.
jq --slurp '
  .[0] as $nuget | .[1] as $npm
  | $nuget
  | .metadata.tools.components += $npm.metadata.tools.components
  | .components += [$npm.metadata.component] + $npm.components
  | .dependencies |= map(
      if .ref == $nuget.metadata.component["bom-ref"]
      then .dependsOn += [$npm.metadata.component["bom-ref"]]
      else . end)
  | .dependencies += $npm.dependencies
' sbom/nuget.json "$scratch/npm.json" > sbom/sbom.json
