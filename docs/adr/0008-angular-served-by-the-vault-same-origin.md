# The vault serves the Angular UI from its own origin and its own signed image

In production the Angular UI's build output is copied into the ASP.NET app's static files when the image is built, and the vault serves it from its own origin. One version, one artifact, one signature and one SBOM cover both. In development, `ng serve` runs on its own port and proxies `/api` to Kestrel, so the browser still sees a single origin.

A separate deployment (an nginx container or a CDN on another origin) was rejected. It would make the session cookie cross-origin, forcing `SameSite=Strict` to loosen and CORS to open, which breaks ADR-0002. It would also mean two artifacts to sign and version, and two CSPs that must agree.

## Consequences

The Dockerfile gains a Node build stage, pinned by digest like the .NET stages. `docker-compose.yml` is unaffected: it runs only the dependencies.
