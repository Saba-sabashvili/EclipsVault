# Angular guards and hidden links are convenience; the server enforces, and says what to show

Angular route guards and hidden navigation never protect anything. Every UI API endpoint enforces its own authorization on every request, exactly as the controllers do today. What the UI may *show* comes from the server: a `/api/ui/me` response lists the areas this session may use. The Angular UI never decides from a hard-coded check such as "clearance is TopSecret". This keeps today's property that the sidebar and the ⌘K palette offer a user only what the server already offered them, with the policy written once.

The application uses Angular's current defaults: standalone components, signals, and running without zone.js (the runtime allowlist in ADR-0003 excludes it). Each area is a lazily loaded route. Forms are reactive, and TypeScript and templates are strict. There is no state-management library.

## Considered Options

- **Decide visibility in TypeScript from the session's clearance.** Rejected. It writes the authorization policy a second time, in a place nothing keeps in step with the server.
