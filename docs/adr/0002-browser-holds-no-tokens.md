# The browser holds no tokens: Angular uses the existing session cookie

The Angular UI authenticates with the vault's existing server-side session cookie (`HttpOnly`, `Secure`, `SameSite=Strict`), served from the same origin as the API. No access, refresh or ID token ever reaches the browser, and nothing auth-related is written to `localStorage` or `sessionStorage`. The ASP.NET Core app already plays the backend-for-frontend role, so no new server tier is added. This is the pattern the IETF's *OAuth 2.0 for Browser-Based Applications* recommends for high-value applications.

We chose this because a token readable by JavaScript can be stolen by any XSS and replayed from the attacker's machine until it expires. That sits outside the per-request revocation (`OnValidatePrincipal`), the honey-token sign-out and the IP blacklist, all of which act on the session. Keycloak SSO is unchanged: an optional, server-side way to prove identity, after which the vault alone decides admission.

## Considered Options

- **Angular performs OIDC itself (code + PKCE) and holds the access token.** Rejected. There is no token issuer for vault accounts: password, TOTP, passkeys, recovery codes, lockout, breached-password screening and break-glass would have to move into Keycloak, or the vault would have to become an OAuth server. Clearance and project are vault-owned and would have to ride in tokens. Immediate revocation would survive only by checking every call against the server, which is the session model with more moving parts.
