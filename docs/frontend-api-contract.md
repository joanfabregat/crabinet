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

`GET /api/v1/shares/{shareId}/events?path={path}` is an authenticated server-sent-events stream for the currently open directory. It emits `invalidate` when a non-recursive kernel watch observes a change and `resync` if the watch becomes unreliable. A connection is bounded to five minutes and then reconnects through normal authentication. Events carry no names, host paths, or file contents; clients debounce them and fetch a fresh directory page. The endpoint never scans the directory or share.

## Browser routes

Directory links use `/browse/{encodedShareId}?path={encodedRelativePath}`. The backend should serve the embedded application shell for `/` and `/browse/*`, while reserving `/api/v1/*` for JSON responses. Browser history and direct navigation therefore work without client-side routing dependencies.

## Previews

`GET /api/v1/shares/{shareId}/preview?path={path}` returns inert UTF-8 source data:

```json
{
  "kind": "code",
  "source": "fn main() {}\n",
  "language": "rust",
  "size": 13,
  "truncated": false
}
```

`kind` is `text`, `code`, `markdown_source`, `html_source`, or `image`. `language` is an optional fixed allowlisted hint. Text and markup source reject oversized, invalid-UTF-8, binary, linked, and special files; the server does not return truncated text. Markdown and HTML remain source data and must never be inserted into the application DOM as unsanitized HTML. Image metadata includes a server-selected `mimeType` and optional `width` and `height`; `source` is empty.

`GET /api/v1/shares/{shareId}/preview/html?path={path}` is the dedicated HTML-source page. It returns source as `text/plain; charset=utf-8`; opening it in a new tab remains inert. `GET /api/v1/shares/{shareId}/preview/html/rendered?path={path}` returns the same validated source as HTML under an HTTP CSP sandbox that blocks scripts, forms, navigation, storage access, and external requests. The frontend may embed rendered HTML only in an iframe with an empty `sandbox` attribute or open that CSP-sandboxed response in a new tab with an isolated opener. It must never add `allow-scripts` or `allow-same-origin`.

`GET /api/v1/shares/{shareId}/preview/image?path={path}` returns bounded PNG, JPEG, GIF, WebP, or AVIF bytes after signature validation. Its fixed response `Content-Type` comes from the detected signature. Filename extensions, uploaded media types, SVG, and arbitrary binary content do not control the response type.

Both endpoints authenticate and authorize every request. Missing grants and missing content are intentionally indistinguishable. See [Preview security contract](previews.md) for the complete response and isolation requirements.

The v1 client offers source and readable Markdown modes without interpreting inline Markdown. Its readable mode recognizes only block headings, lists, quotations, paragraphs, and fenced code; every file-derived value is inserted as a text child. Raw HTML, links, images, and embeds therefore remain visible text and never become elements, attributes, or requests. Shiki code tokens are likewise rendered as text children. HTML has rendered and source tabs plus isolated new-tab actions for each representation; only the in-panel rendered endpoint enters an empty-sandbox iframe. Browser history records only validated virtual paths and side/full-screen display mode, never file contents.
