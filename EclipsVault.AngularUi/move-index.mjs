// Moves the built index.html out of wwwroot, where the vault's static-file middleware would serve it
// to anyone at /ui/index.html. Under AngularUi/ only the server's route table serves it, behind a
// session, on the paths the Angular UI owns (AngularUiRoutes.cs). The Angular builder cannot write
// the index outside its output folder itself.
import { mkdirSync, renameSync } from 'node:fs';

mkdirSync('../EclipsVault.Web/AngularUi', { recursive: true });
renameSync('../EclipsVault.Web/wwwroot/ui/index.html', '../EclipsVault.Web/AngularUi/index.html');
