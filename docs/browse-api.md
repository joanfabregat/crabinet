# Authenticated browse API

All endpoints are under `/api/v1` and require authentication middleware to insert an `AuthenticatedIdentity` request extension. The browse module does not accept identity headers and has no development-user fallback. A missing verified identity returns `401`. An unknown share, an ungranted share, a missing path, and an unsupported filesystem object use the same `404` response where disclosing the difference would expose information.

## Share discovery

`GET /api/v1/shares` returns only configured shares granted to the current identity, including the configured display name. Grants for removed or misspelled share IDs are omitted. The global read-only policy reduces effective access before it is returned. Wire access values are exactly `read` and `read-write`.

```json
{
  "shares": [
    { "id": "documents", "name": "Documents", "access": "read" }
  ]
}
```

## Directory listing

`GET /api/v1/shares/{shareId}/directory?path=&limit=100&cursor=` lists the share root when `path` is absent or empty. A nonempty path uses the validated slash-separated virtual path grammar documented in `filesystem-security.md`, including its 64-component depth limit; a deeper path returns `400 invalid_request`. A directory at the limit still lists its entries, but they cannot be opened.

Entries are sorted deterministically with directories first and then by normalized name. `limit` is nonzero and cannot exceed the configured page maximum. The service also caps the total number of entries it will inspect, preventing an attacker-controlled directory from causing unbounded allocation merely because deterministic sorting is required. A directory above that cap currently returns `413` (`too_large`). At most 16 listings are scanned concurrently across the process and 8 per authenticated user, counting Trash listings; further requests receive `429` with code `busy` and `Retry-After`. An entry removed between reading the directory and inspecting it is omitted rather than failing the listing.

```json
{
  "shareId": "documents",
  "path": "reports",
  "entries": [
    {
      "name": "archive",
      "kind": "directory"
    },
    {
      "name": "summary.md",
      "kind": "file",
      "size": 1234
    }
  ],
  "nextCursor": "opaque-value-when-another-page-exists"
}
```

The cursor contains no host path. Its HMAC binds the authenticated subject, effective access grant, share ID, virtual path, offset, and a fingerprint of the sorted listing structure (each entry's kind, name, and file identity). Tampering, use by another user or grant, use for another directory, or an entry being added, removed, renamed, or replaced between pages rejects the cursor with `409`; clients should restart from the first page. Size and modification-time changes, such as a file still being written, do not invalidate the cursor. `nextCursor` is omitted on the final page. File entries include `size`; directory entries omit it. Modification time remains optional in the frontend contract and is omitted until a lightweight RFC 3339 formatter is part of the reviewed dependency set.

## Single-entry metadata

`GET /api/v1/shares/{shareId}/metadata?path=relative/path` reopens one entry through the same authorization and no-follow capability checks and returns its safe metadata plus a weak concurrency validator:

```json
{
  "shareId": "documents",
  "path": "reports/summary.md",
  "name": "summary.md",
  "kind": "file",
  "size": 1234,
  "etag": "W/\"opaque-validator\""
}
```

Directory metadata omits `size`. The ETag is also returned in the response header and changes after an atomic entry replacement without exposing inode, device, owner, or ambient path information.

Metadata lookups and the pre-commit lookup of a move or move-to-Trash share one gate for blocking filesystem work that no narrower limit bounds: at most 64 run concurrently across the process and 16 per authenticated user, so a slow disk or network filesystem cannot let them occupy the runtime's blocking thread pool. Further requests receive `429` with code `busy` and `Retry-After`. Session lookups and sign-in are not counted against this gate.

## Inert UTF-8 text

`GET /api/v1/shares/{shareId}/text?path=relative/path` returns a configured-size-capped file as a JSON string. Invalid UTF-8 returns `415`, and a file above the text cap returns `413`. HTML, SVG, Markdown, and code are data inside JSON at this boundary and are never emitted as an executable document.

The response includes `size`, `mimeType`, and a content-derived `etag`, as well as `X-Content-Type-Options: nosniff` and `Cache-Control: no-store, private`. Text reads and previews share a limit of four concurrent requests that buffer a whole file across the process and two per authenticated user; further requests receive `429` with code `busy` and `Retry-After`.

## Streaming download

`GET /api/v1/shares/{shareId}/download?path=relative/path` streams from the already validated regular-file handle. It never buffers the whole file. Each stream is capped by the configured maximum file size and fixed read chunk size, and dropping the response cancels the stream and closes the handle. At most 64 downloads stream concurrently across the process and 8 per authenticated user, counting streamed image previews (`/preview/image`); a slot is held until the response body completes or is dropped, not merely until headers are sent, and further requests receive `429` with code `busy` and `Retry-After`. Eight per user covers a few parallel downloads plus a media player's overlapping range requests while preventing one user from exhausting file descriptors.

The endpoint supports one RFC-style byte range (`start-end`, `start-`, or `-suffix`), returns `206` with `Content-Range` when applicable, and returns `416` with `Content-Range: bytes */{length}` only for an unsatisfiable range (a first byte at or beyond the end, or `bytes=-0`). As RFC 9110 permits, a syntactically invalid range (including an inverted range or a number with a sign), another range unit, or a multi-range request is ignored and the complete representation is returned with `200`; multiple ranges are intentionally unsupported. `If-None-Match` produces `304`. Download ETags are weak validators derived from file identity, nanosecond modification time, size, share, and virtual path; an `If-Range` request therefore falls back to a complete `200` response as required for weak validators.

Downloads include a safe ASCII fallback plus RFC 5987 UTF-8 filename in `Content-Disposition`. Every file, including raw HTML and SVG, is an attachment. Responses also set `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`, `Accept-Ranges: bytes`, an explicit MIME type, ETag, and content length. The MIME type comes from the file extension, except that JavaScript, CSS, and WebAssembly types are replaced by `application/octet-stream`. An attachment disposition does not stop `<script src>` or `<link rel="stylesheet">` from loading a same-origin URL, so this, together with `nosniff`, keeps the application CSP's `'self'` sources from covering user files.

Every browse response, including share discovery, listings, metadata, text, and downloads, sets `Cache-Control: no-store, private` so authenticated content does not remain in the browser disk cache after sign-out. ETags remain available for explicit `If-None-Match`, `If-Range`, and mutation `If-Match` requests.

## Default resource limits

| Limit | Default |
| --- | ---: |
| Directory page | 100 entries |
| Maximum requested page | 200 entries |
| Maximum directory scan | 10,000 entries |
| UTF-8 text read | 1 MiB |
| Download | 1 GiB |
| Streaming read chunk | 64 KiB |

All values are startup configuration inputs through `BrowseLimits`; invalid zero or internally inconsistent limits prevent browse-state construction. Startup must also provide a non-zero 32-byte cursor HMAC secret from the authenticated application configuration; it is never accepted from a request.
