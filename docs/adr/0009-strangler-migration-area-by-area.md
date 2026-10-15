# Migrate area by area into main, deleting each area's Razor views in the same PR

The Legacy UI is replaced one area at a time (for example Activity, Sessions, Secrets). Each area is rebuilt in Angular to match the current behaviour, proven by end-to-end tests, and merged to `main` in its own PR. The same PR deletes that area's Razor views and controller actions. Angular serves the migrated areas and Razor serves the rest, both on the same session, so the vault is complete and demonstrable at every commit.

The deadline for the Angular requirement is not yet known, which is why this beats building everything on a long-lived branch and merging once: a big bang drifts from the fixes landing on `main` and shows nothing until it is entirely done. The `angular-migration` branch carries only the groundwork: these ADRs, the Angular workspace, hosting, and the test setup.
