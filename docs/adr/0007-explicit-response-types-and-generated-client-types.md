# Explicit UI API response types, described by OpenAPI, with generated TypeScript types

UI API endpoints return response types defined in `EclipsVault.Web`, mapped explicitly from Core results, much as views get ViewModels today. Core types are never serialized as they are. A field added to a Core type must not silently appear on the wire, because in a vault that is how something sensitive leaks.

The UI API is described with ASP.NET Core's built-in OpenAPI support. The document is served only in Development or produced at build time, so production does not advertise its surface. The Angular UI's TypeScript types are generated from it at build time by a dev-only tool (allowed and audited under ADR-0003), and CI fails if the committed types differ from the API. Hand-written TypeScript interfaces were the considered alternative; they drift silently.
