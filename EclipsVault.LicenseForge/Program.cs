using EclipsVault.LicenseForge.Cli;

// EclipsVault License Forge — the vendor-side offline tool that generates the signing keypair
// (`keygen`) and mints signed license tokens (`mint`). This entry point stays a single line on
// purpose: the CLI host lives in Cli/, the verbs in Commands/, and every byte of output in Rendering/.
return ForgeCli.Run(args);
