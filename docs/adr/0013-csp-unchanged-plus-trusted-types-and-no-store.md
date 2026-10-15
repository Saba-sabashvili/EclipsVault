# Angular fits the existing strict CSP, adds Trusted Types, and the UI API is never cached

The Content Security Policy stays as it is (`script-src 'self'; style-src 'self'`, no inline code), with one addition: `require-trusted-types-for 'script'; trusted-types angular angular#bundler`. Angular supports this browser-enforced XSS protection natively. While the Legacy UI exists, Trusted Types is sent only on the documents the Angular UI serves, because the legacy `site.js` writes `innerHTML`; the final cleanup makes it global. To fit the policy:

- Styles are global stylesheets ported from `site.css`; components declare no styles, because Angular injects component styles as runtime `<style>` tags.
- The build's critical-CSS inlining is off, because it emits an inline `onload` handler.
- Any use of Angular's `bypassSecurityTrust*` fails the lint.
- Every end-to-end test fails on any CSP violation.

A per-request nonce allowing component styles was rejected. It would make the server render `index.html` per request: more moving parts, no security gain.

Every UI API response carries `Cache-Control: no-store`. Today secret values only ever appear in HTML, which is already no-store. In the Angular UI a reveal is a JSON response, which nothing marked no-store, so without this rule decrypted values could land in the browser's disk cache.
