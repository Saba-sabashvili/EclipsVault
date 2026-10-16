#!/usr/bin/env bash
# Writes sbom/sbom.json: one CycloneDX bill of materials for what the image ships, the NuGet packages
# of EclipsVault.Web plus the npm runtime packages of the Angular UI it serves (ADR-0003). The release
# attests this file to the image, and CI's sbom job runs the same script on every change, so a broken
# SBOM fails a PR before it can fail a tag.
#
# Needs: a restored solution, the CycloneDX dotnet tool, Node, and jq.
set -euo pipefail

dotnet CycloneDX EclipsVault.Web/EclipsVault.Web.csproj -o sbom -fn nuget.json -F Json

# The npm half lists only the runtime packages, because they are what ships. They are installed
# alone into a scratch copy of the UI's manifest, which leaves the workspace's node_modules as it
# was. It is written in the NuGet half's spec version, so the merged document has one.
spec=$(jq -r .specVersion sbom/nuget.json)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
cp EclipsVault.AngularUi/package.json EclipsVault.AngularUi/package-lock.json "$scratch"
(cd "$scratch" &&
  npm ci --omit=dev &&
  npx --yes @cyclonedx/cyclonedx-npm@6.0.1 --omit dev --spec-version "$spec" --output-file npm.json)

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
