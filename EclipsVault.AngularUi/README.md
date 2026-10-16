# EclipsVault Angular UI

The browser application replacing the Legacy UI. It lives outside the .NET solution (ADR-0015).
Use the Node version in `.nvmrc`.

- `npm ci --ignore-scripts`: install from the lockfile without dependency install scripts.
- `npm run lint`: ESLint with angular-eslint.
- `npm test`: the Vitest unit tests. `npm run test:build-checks` tests the build's own checks.
- `npm run build`: production build into `../EclipsVault.Web/wwwroot/ui/` (bundles) and
  `../EclipsVault.Web/AngularUi/index.html` (the document the vault serves on Angular-owned paths).
  It fails if the lockfile holds a runtime package outside `@angular/*`, `rxjs` and `tslib`
  (ADR-0003), or if the index is left in wwwroot or carries inline code the CSP would block.
- `npm start`: dev server on http://localhost:4200, proxying `/api` to the vault on https://localhost:7443.
