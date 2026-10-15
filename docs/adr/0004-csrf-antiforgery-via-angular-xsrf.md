# CSRF: keep ASP.NET antiforgery, delivered through Angular's built-in XSRF support

Every unsafe request from the Angular UI carries an antiforgery token, validated by the existing global `AutoValidateAntiforgeryToken` filter. The server issues the request token in a JavaScript-readable `XSRF-TOKEN` cookie, and Angular's `HttpClient` echoes it in the `X-XSRF-TOKEN` header on same-origin POST/PUT/PATCH/DELETE. The token is bound to the signed-in identity, so the UI fetches a fresh one after every sign-in and sign-out.

`SameSite=Strict` on the session cookie would stop most cross-site forgery on its own. We keep the token anyway because "same-site" includes every subdomain of the vault's domain, and a compromised sibling subdomain is same-site. Dropping antiforgery in favour of SameSite plus a custom header was the considered alternative.
