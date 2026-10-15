# EclipsVault Angular UI

The browser application replacing the Legacy UI. It lives outside the .NET solution (ADR-0015).
Use the Node version in `.nvmrc`.

- `npm ci`: install from the lockfile.
- `npm run build`: production build into `../EclipsVault.Web/wwwroot/ui/` (bundles) and
  `../EclipsVault.Web/AngularUi/index.html` (the document the vault serves on Angular-owned paths).
- `npm start`: dev server on http://localhost:4200, proxying `/api` to the vault on https://localhost:7443.
