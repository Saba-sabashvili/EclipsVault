# The Angular workspace lives at the repo root, outside the .NET solution

The Angular UI lives in a top-level `EclipsVault.AngularUi/` folder that is not part of `EclipsVault.slnx` and is not hooked into MSBuild. `dotnet build`, `dotnet test` and CI's locked-mode restore never need Node. The Dockerfile's Node stage builds the workspace and copies its output into the web app's `wwwroot`. Nesting it as `EclipsVault.Web/ClientApp/` with an MSBuild hook was rejected: every .NET build would then depend on Node and npm.
