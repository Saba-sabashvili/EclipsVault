# UI API errors are RFC 9457 Problem Details with a stable code

Every UI API failure is an RFC 9457 Problem Details response carrying a stable `code` extension (e.g. `audit_unavailable`, `step_up_required`, `forbidden` with `reasons`, `not_found`, `throttled`), so one Angular interceptor can act on them. The status mapping stays what it is today: 404, 409 for a refused legacy envelope, 402 for an unlicensed premium feature, 429, and 503 when the audit trail cannot be written. A honey-token trip answers a plain 404, and the already-revoked session gets a 401 on its next request. No response ever carries exception details.

The Public API keeps its existing `{ error, reasons }` shape, because it is a published contract.
