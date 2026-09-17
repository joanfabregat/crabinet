# Frontend API contract

This document records the assumptions made by the Preact file-browser shell. The Rust handlers should implement this contract under `/api/v1`, or update the typed client and its tests in the same change.

## Transport and errors

- All calls are same-origin and use the server-managed session cookie. The frontend never reads the cookie and never stores credentials, session identifiers, or CSRF values in web storage.
- JSON responses use `Content-Type: application/json`. Error responses may use `application/problem+json` and return `{ "code": string, "message": string, "requestId": string }`.
- The frontend maps status codes to structured errors and treats every `401` after authentication as session expiry. It intentionally shows a generic login failure instead of displaying server-provided authentication details.
- Safe `GET` requests retry once after a network error or `502`, `503`, or `504`. Authentication mutations are never automatically retried. Every call accepts an `AbortSignal`.
- Successful JSON is runtime-validated at the client boundary. Wrong session fields, mismatched share/path values, invalid grants, unsafe filename components, and malformed pagination data become `invalid-response` errors instead of entering UI state.
- The server remains authoritative for authentication, share membership, permissions, path resolution, and every future mutation. UI access labels are informational and are never an authorization control.

## Session

`GET /api/v1/session` returns `200` with:

```json
{
  "user": { "id": "user-id", "username": "joan", "displayName": "Joan" },
  "shares": [{ "id": "docs", "name": "Documents", "access": "read-write" }],
  "csrfToken": "opaque-value"
}
```

An anonymous or expired session returns `401`. `csrfToken` is held in memory and sent on authenticated state-changing requests; it is not a session identifier.

`POST /api/v1/auth/login` accepts `{ "username": string, "password": string }`, rotates the session identifier, and returns the same session shape. Login failures return a generic `401` response. The server should validate `Origin`/`Sec-Fetch-Site`, rate-limit attempts, and never include credential details in responses or logs.

`POST /api/v1/auth/logout` requires `X-CSRF-Token`, invalidates the server session, expires its cookie, and returns `204`.

## Directory browsing

`GET /api/v1/shares/{shareId}/directory?path={path}&limit=100&cursor={opaque}` returns:

```json
{
  "shareId": "docs",
  "path": "projects/index",
  "entries": [
    { "name": "src", "kind": "directory", "modifiedAt": "2026-09-16T18:30:00Z" },
    { "name": "README.md", "kind": "file", "size": 2048, "modifiedAt": "2026-09-16T18:30:00Z" }
  ],
  "nextCursor": "opaque-or-omitted"
}
```

- `path` is a slash-separated relative path; the empty string is the share root. Canonical components are non-empty NFC Unicode and reject dot segments, `/` or `\\`, control characters, percent triplets, unpaired surrogates, and trailing dots or spaces. The client uses this grammar to avoid ambiguous routes, but it is not an authorization boundary. The server must independently validate paths and resolve them within the configured share root.
- `name` is one component using the same canonical grammar, never HTML. The frontend inserts it only as text.
- Results are ordered deterministically by the server, with the cursor tied to that ordering. The frontend preserves server order and de-duplicates page-boundary repeats by `(kind, name)` so concurrent directory changes do not produce duplicate rows.
- A cursor is scoped to the authenticated user, effective share grant, share, path, ordering, and relevant directory generation. Invalid or stale cursors return a structured `409` or `404` without leaking host paths.
- Access is `read` or `read-write` after resolving user and share policy. The server checks it on every request.

## Browser routes

Directory links use `/browse/{encodedShareId}?path={encodedRelativePath}`. The backend should serve the embedded application shell for `/` and `/browse/*`, while reserving `/api/v1/*` for JSON responses. Browser history and direct navigation therefore work without client-side routing dependencies.
