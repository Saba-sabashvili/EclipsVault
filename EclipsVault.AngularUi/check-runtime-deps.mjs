// Fails the build when the UI would ship a runtime package outside @angular/*, rxjs and tslib
// (ADR-0003). It reads the lockfile, so a package another runtime package pulls in counts too.
// Adding one needs a new ADR, not a change to this list.
import { readFileSync } from 'node:fs';

const allowed = (name) => name.startsWith('@angular/') || name === 'rxjs' || name === 'tslib';

/** The package installed at a lockfile path: what follows its last `node_modules/`. */
const packageAt = (path) => path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);

/** Names of the non-dev packages in a package-lock.json that the allowlist does not cover. */
export function disallowedRuntimePackages(lock) {
  return (
    Object.entries(lock.packages)
      .filter(([path, entry]) => path !== '' && !entry.dev)
      // An aliased install (`"x": "npm:y"`) is locked at x's path with the real package as `name`.
      .map(([path, entry]) => entry.name ?? packageAt(path))
      .filter((name) => !allowed(name))
  );
}

if (import.meta.main) {
  const disallowed = disallowedRuntimePackages(
    JSON.parse(readFileSync('package-lock.json', 'utf8')),
  );
  if (disallowed.length > 0) {
    console.error(
      `Runtime packages outside @angular/*, rxjs and tslib (ADR-0003): ${disallowed.join(', ')}`,
    );
    process.exit(1);
  }
}
