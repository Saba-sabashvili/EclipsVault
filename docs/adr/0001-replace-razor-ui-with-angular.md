# Replace the Razor UI with Angular, completely

An external requirement says EclipsVault's frontend must be Angular. So every Razor view in `EclipsVault.Web` is replaced by an Angular application, and the migration is finished only when no `.cshtml` remains. That includes the sign-in, second-factor, passkey, recovery and break-glass screens, which a migration without that requirement might have left server-rendered.

The backend stays ASP.NET Core on .NET. Rewriting it (Rust, Go) or using a non-Angular frontend (React, Next.js) was ruled out for this migration: the requirement is an Angular frontend, and a backend rewrite would trade a tested, security-reviewed codebase for one that has to rediscover its fixes. Whether to move languages once the requirement no longer applies is a separate, later decision. The API contract this migration introduces is what would make such a move possible.

The migration does not lower the security bar. Every invariant in `AGENTS.md` and every in-scope control in `docs/THREAT_MODEL.md` holds after the migration exactly as before. Where the Angular UI cannot meet one, the screen stays in Razor until it can.
