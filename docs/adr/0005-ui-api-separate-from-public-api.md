# The UI API is separate from the Public API, and neither accepts the other's credentials

The Angular UI calls its own endpoints under `/api/ui/`, which authenticate with the session cookie only. The Public API (`/api/v1/`) stays API-key-only and unchanged. An endpoint that accepted both would apply CSRF rules and API-key scopes inconsistently depending on who called it, and every UI change could break operators' integration scripts. A test pins the separation: no UI API endpoint accepts an API key, and no Public API endpoint accepts a session.
