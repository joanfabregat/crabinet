# Frontend API contract

This document records the assumptions made by the Preact file-browser shell. The Rust handlers should implement this contract under `/api/v1`, or update the typed client and its tests in the same change.

## Transport and errors

- All calls are same-origin and use the server-managed session cookie. The frontend never reads the cookie and never stores credentials, session identifiers, or CSRF values in web storage.
- JSON responses use `Content-Type: application/json`. Error responses may use `application/problem+json` and return `{ "code": string, "message": string, "requestId": string }`.
- The frontend maps status codes to structured errors and treats every `401` after authentication as session expiry. A few codes name a state rather than a failed request and get their own message: `path_too_deep` (`400`), and `share_too_large_to_measure` and `share_too_deep_to_measure` (`507`, also upload outcomes), which mean the share's quota cannot be measured until an operator intervenes. It intentionally shows a generic login failure instead of displaying server-provided authentication details.
- Safe `GET` requests retry once after a network error or `502`, `503`, or `504`. Authentication mutations are never automatically retried. Every call accepts an `AbortSignal`.
- Successful JSON is runtime-validated at the client boundary. Wrong session fields, mismatched share/path values, invalid grants, unsafe filename components, and malformed pagination data become `invalid-response` errors instead of entering UI state.
- The server remains authoritative for authentication, share membership, permissions, path resolution, and every future mutation. UI access labels are informational and are never an authorization control.

## Session

`GET /api/v1/session` returns `200` with:

```json
{
  "user": { "id": "user-id", "username": "joan", "displayName": "Joan" },
  "shares": [{ "id": "docs", "name": "Documents", "access": "read-write" }],
  "defaultFolder": { "shareId": "docs", "path": "projects/crabinet" },
  "preferences": { "showHiddenFiles": false, "theme": "system" },
  "csrfToken": "opaque-value"
}
```

An anonymous or expired session returns `401`. `csrfToken` is held in memory and sent on authenticated state-changing requests; it is not a session identifier.

`user.pictureUrl` is optional. When present, it is an accepted Google profile image or, when `auth.gravatar_enabled` is set, a Gravatar URL derived from the configured email address; the browser loads that external image. See [account pictures](authentication.md#account-pictures).

`defaultFolder` is `null` when no start folder is selected or the saved folder is no longer accessible. Opening `/` goes to this folder when present; a direct `/{shareId}/…` link keeps its own destination. `PUT /api/v1/preferences` accepts `{ "defaultFolder": { "shareId": "docs", "path": "projects/crabinet" } }` or `{ "defaultFolder": null }`, with same-origin and session-bound CSRF checks. The server accepts only an existing directory in a share granted to the current user, stores its virtual share ID and path in SQLite, and returns the new `defaultFolder` value. Passwords and host filesystem paths are not stored in this preference.

`preferences` holds the account's display settings, with `{ "showHiddenFiles": false, "theme": "system" }` for an account that never changed them. `theme` is `system`, `light` or `dark`. `PUT /api/v1/preferences/display` accepts any subset of these fields, such as `{ "theme": "dark" }`, with the same same-origin and session-bound CSRF checks. Omitted fields and the start folder keep their saved values; `null`, an unknown theme or an unknown field returns `400 invalid_request`. The response is the full saved `preferences` object. The browser also keeps a copy of the theme in `localStorage` so the sign-in page and first paint use it; a signed-in session replaces that copy with the account's value. A light or dark choice or a hidden-files choice saved in the browser before these settings followed the account is sent to the account once, when the account still has the default.

`GET /api/v1/auth/methods` reports the enabled sign-in methods, including `passkeyEnabled`. `POST /api/v1/auth/login` accepts `{ "username": string, "password": string }`, where `username` may be a configured username or email address. It rotates the session identifier and returns the same session shape. Login failures return a generic `401` response. The server validates `Origin`/`Sec-Fetch-Site`, rate-limits attempts, and never includes credential details in responses or logs. When OIDC is enabled, the browser starts at `GET /api/v1/auth/oidc/start`; the server handles the fixed callback and creates the same local session after verifying the provider identity. The sign-in page is always shown before choosing a method.

When passkeys are enabled, `POST /api/v1/auth/passkeys/login/start` accepts `{}` and starts a discoverable sign-in without an account name. A `{ "username": string }` body is accepted for compatibility but ignored, so the response is identical for every input. It returns `{ "flowId": string, "options": { "publicKey": PublicKeyCredentialRequestOptionsJSON } }`. `POST /api/v1/auth/passkeys/login/finish` accepts `{ "flowId", "credential" }` and returns the normal session shape with a session cookie. For a signed-in user, `GET /api/v1/auth/passkeys` lists that user's `{ id, name, createdAt, lastUsedAt }` records. Registration uses `POST /api/v1/auth/passkeys/register/start` with `{ "name" }`, then `/register/finish` with `{ "flowId", "credential" }`; newly registered passkeys require a discoverable credential. Each mutation requires the session CSRF token. `PATCH /api/v1/auth/passkeys/{id}` with `{ "name" }` renames a key, and `DELETE` on the same path removes it. Registration start returns `403` with code `reauthentication_required` when the session signed in more than 10 minutes ago. Registration challenge state is bound to the initiating session and expires after five minutes; sign-in challenges expire after two minutes.

`POST /api/v1/auth/logout` requires `X-CSRF-Token`, invalidates the server session, expires its cookie, and returns `204`.

## Directory browsing

Trash is a separate per-share view, not a virtual `.crabinet` folder. `GET /api/v1/shares/{shareId}/trash?limit=100&cursor={opaque}` returns one page, newest first: `{ "shareId": "docs", "items": [{ "id": "opaque-id", "originalPath": "reports/old.txt", "kind": "file", "deletedAt": "2026-09-27T12:00:00Z", "deletedBy": "joan", "expiresAt": "2026-10-27T12:00:00Z" }], "retentionDays": 30, "nextCursor": "opaque-or-omitted" }`, where `retentionDays` is `server.trash_retention_days`. It is available to every user granted the share. `limit` is 1–200; `nextCursor` is omitted on the last page. The cursor names the last item's position and is HMAC-bound to the user, share, and effective access, so a forged, altered, or replayed cursor returns `409`; concurrent deletes, restores, and purges do not invalidate it. The client requests 100 items per share, shows a "Load more" button under each share with more items, and de-duplicates repeats by `id`. Items whose stored data is damaged or that vanish during the listing are left out rather than failing the page. `DELETE /api/v1/shares/{shareId}/entry?path=...` returns a `trashId` for Undo, or `400 path_too_deep` for a directory holding entries nested more than 64 levels deep. A writer restores through `POST /api/v1/shares/{shareId}/trash/{id}/restore` with `{}` for the original path or `{ "destination": "other/path" }` after a conflict, permanently purges one item through `DELETE /api/v1/shares/{shareId}/trash/{id}`, and empties a share's whole Trash, loaded or not, through `POST /api/v1/shares/{shareId}/trash/empty`. That returns `{ "shareId": "docs", "outcome": "success", "purged": 250, "failed": 0, "moreRemaining": false }`; `failed` counts items that could not be deleted and stay in Trash, and `moreRemaining: true` means the request ran out of time and the client repeats it. Empty Trash in the client sends it for every writable share with items, repeating while `moreRemaining` is true (at most 50 times per share), then reloads Trash. The server enforces grants and no-replace semantics for every action. The sidebar shows Trash independently of the hidden-files preference; `.crabinet` remains inaccessible.

`GET /api/v1/shares/{shareId}/directory?path={path}&limit=100&cursor={opaque}` returns:

```json
{
  "shareId": "docs",
  "path": "projects/crabinet",
  "entries": [
    {
      "name": "src",
      "kind": "directory",
      "modifiedAtMs": 1789599000000
    },
    {
      "name": "README.md",
      "kind": "file",
      "size": 2048,
      "modifiedAtMs": 1789599000000
    }
  ],
  "nextCursor": "opaque-or-omitted"
}
```

- `path` is a slash-separated relative path of at most 64 components; the empty string is the share root. The server rejects a deeper request path with `400 invalid_request`, and a move or restore whose entries would end deeper with `400 path_too_deep`. Canonical components are non-empty NFC Unicode and reject dot segments, `/` or `\\`, control characters, percent triplets, unpaired surrogates, and trailing dots or spaces. The client uses this grammar to avoid ambiguous routes, but it is not an authorization boundary. The server must independently validate paths and resolve them within the configured share root.
- `name` is one component using the same canonical grammar, never HTML. The frontend inserts it only as text.
- Results are ordered deterministically by the server, with the cursor tied to that ordering. The frontend preserves server order and de-duplicates page-boundary repeats by `(kind, name)` so concurrent directory changes do not produce duplicate rows.
- A cursor is scoped to the authenticated user, effective share grant, share, path, ordering, and relevant directory generation. Invalid or stale cursors return a structured `409` or `404` without leaking host paths.
- Access is `read` or `read-write` after resolving user and share policy. The server checks it on every request.

`GET /api/v1/shares/{shareId}/events?path={path}` is an authenticated server-sent-events stream for the currently open directory. It emits `invalidate` when a non-recursive kernel watch observes a change and `resync` if the watch becomes unreliable. A connection is bounded to 60 seconds, carries a `retry: 1000` reconnection hint, and then reconnects through normal authentication. The server also re-checks the stream's session every 15 seconds, without extending it, and ends the stream once the session is signed out, expired, or revoked; the reconnect then fails authentication. Events carry no names, host paths, or file contents; clients debounce them and fetch a fresh directory page. The endpoint never scans the directory or share.

`GET /api/v1/shares/{shareId}/metadata?path={path}` returns mutation validators and optional filesystem timestamps:

```json
{
  "shareId": "docs",
  "path": "README.md",
  "name": "README.md",
  "kind": "file",
  "size": 2048,
  "modifiedAtMs": 1789599000000,
  "accessedAtMs": 1789599600000,
  "createdAtMs": 1789513200000,
  "etag": "W/\"opaque-validator\""
}
```

`modifiedAtMs`, `accessedAtMs` and `createdAtMs` are Unix-epoch milliseconds and are omitted when the filesystem does not expose them; clients must treat all three as optional. Access time is filesystem metadata, not an application audit trail, and may be approximate under `relatime` or unavailable under `noatime`. The modification time is the same filesystem value the mutation validator covers, so a change to it also changes `etag`; the access and creation times do not participate in the validator.

`GET /api/v1/shares/{shareId}/archive?path={path}` downloads a folder, or the share root when `path` is omitted, as a ZIP attachment, and `?path={a}&path={b}…` downloads a selection of entries of one folder, each at the archive's top level (see [selection archives](browse-api.md#selection-archives)). The folder heading offers the current folder's archive for every grant, each folder row offers its own (**Download as ZIP**), and the selection bar offers the selection's. Because a refusal (`413 too_large`, `400 path_too_deep`, `429 busy`, `404`) is decided before the body starts, the client first fetches the URL, cancels the body once the headers arrive, and on success hands the URL to the browser as a download; a refusal becomes an error toast and the page stays. A failure after the body started, such as a file changing during the transfer, is reported by the browser's download manager. The client refuses a selection of more than 1,000 entries itself, with the same toast. [Browse API](browse-api.md#folder-archive) has the format and limits. Each file row also offers **Download**, a plain link to `/download` with the attachment disposition, beside the preview panel's own Download link.

Each row's file-type icon doubles as a checkbox labelled "Select {name}": the checkbox replaces the icon while the row is hovered or holds focus, and on every row once anything is selected; on touch screens a tap on the icon toggles the row. Space toggles the focused checkbox, Shift+click selects or deselects the range from the last toggled row, and Escape inside the folder panel clears the selection. Toggling a checkbox never opens or previews the row, and rows stay draggable. The selection is keyed by name within the listed folder: it is cleared when the folder, share, or hidden-file setting changes, and an entry that disappears on refresh (including a server-sent refresh) leaves it for good. While anything is selected, a toolbar ("Selection actions") above the list shows a select-all checkbox, the count, **Download as ZIP**, **Delete** on writable shares, and a clear button. Delete asks once ("Move N items to Trash?") and then moves the entries one at a time; see [bulk moves to Trash](mutations.md#bulk-moves-to-trash).

## Browser routes

Directory links use `/{encodedShareId}/{encodedSegment}/…`, one encoded segment per folder name. A file previewed from its own folder is addressed by its own path, such as `/docs/projects/README.md`; the app lists that path, and when the server reports it missing it asks for the path's metadata and, for a file, opens the parent folder with the file previewed. The resolved route is kept in `history.state`, so reloads and back/forward do not repeat the lookup. `?view=full` selects the full-screen preview, and `?preview={encodedPath}` remains for a file outside the listed folder. Former `/browse/{shareId}?path=…&preview=…` links still resolve and are rewritten in place. The backend serves the embedded application shell for every non-asset path outside `/api/` and `/health/`, so share IDs that would shadow a top-level URL (`api`, `assets`, `browse`, `health`, `trash`, `src`, `node_modules`, `index.html`, `favicon.ico`, `crabinet.png`, `google-g.png`) are rejected at startup. Browser history and direct navigation therefore work without client-side routing dependencies.

## Previews

`GET /api/v1/shares/{shareId}/preview?path={path}` returns inert UTF-8 source data:

```json
{
  "kind": "code",
  "source": "fn main() {}\n",
  "language": "rust",
  "size": 13,
  "truncated": false,
  "openable": true,
  "renderable": false,
  "thumbnailable": false
}
```

`kind` is `text`, `code`, `markdown_source`, `html_source`, `svg`, `image`, `pdf`, `audio`, `video`, or `raw`. `language` is an optional fixed allowlisted hint. Text and markup source reject invalid-UTF-8, binary, linked, and special files with `415`, whatever their size. A text-like file above the preview limit returns its head with `truncated: true`, `size` for the whole file, and `shownBytes` and `shownLines` for the head (at most 64 KiB and 1,000 lines, cut after a line feed, or on a character boundary for one long line; see [Previews](previews.md#large-text-files)); the client rejects a head whose fields do not match its `source`, head fields on a whole document, and a truncated streamed document. The panel shows a head with the notice "Showing the first {lines} lines ({shown}) of {total}. Open in new tab or download for the full file.", offers no **Edit**, and shows large HTML as source only. `svg` is an SVG document within the render limit (`max_render_size`), recognized from its content, with `language: "xml"`; its `source` is the whole file within the preview limit and a head above it, and the panel shows the whole image from `/preview/svg` beside that source. `renderable` is `true` only for an `html_source` document within the render limit, whole or a head, and the client rejects it on any other kind; the full-window viewer frames the rendered endpoint only when it is `true`, and the panel offers that viewer beside a large HTML file's head. Markdown and HTML remain source data and must never be inserted into the application DOM as unsanitized HTML. The streamed kinds (`image`, `pdf`, `audio`, `video`) are classified from the file's signature, are not bound by the preview size limit, and carry a server-selected `mimeType` and an empty `source`; images also carry optional `width` and `height`. The client accepts only the media types the server derives for each kind. `openable` is `true` when the UI may offer **Open in new tab** (images, PDF, SVG, and text-like kinds, heads included) and `false` for audio and video, which play only in the panel. `thumbnailable` is `true` when the panel should show `/thumbnail` instead of the original: PNG and JPEG images, still GIF and WebP images, and every `raw` document; an animated GIF or WebP is `false`, so its original plays. A `raw` document is a camera RAW file with an embedded JPEG preview; it has an empty `source`, no `mimeType` or dimensions, `openable: false`, and `thumbnailable: true`, and the client rejects any other combination.

`GET /api/v1/shares/{shareId}/preview/html?path={path}` is the dedicated HTML-source page. It returns source as `text/plain; charset=utf-8`; opening it in a new tab remains inert. `GET /api/v1/shares/{shareId}/preview/html/rendered?path={path}` streams the whole file, checked on its header like the source, as HTML under an HTTP CSP sandbox that blocks scripts, forms, storage access, and external requests, with the validators and byte ranges of `/open` and a download slot. The frontend may load rendered HTML only in an iframe with an empty `sandbox` attribute, never as a top-level document, which a CSP sandbox does not stop navigating itself; a request whose `Sec-Fetch-Dest` is present and not `iframe` receives a `403` plain-text notice instead. It must never add `allow-scripts` or `allow-same-origin`. The source endpoint answers `413 preview_too_large` for a file above the preview limit, and the rendered endpoint for a file above the render limit, instead of serving or rendering a head.

`GET /api/v1/shares/{shareId}/preview/image?path={path}` returns bounded PNG, JPEG, GIF, WebP, or AVIF bytes after signature validation. Its fixed response `Content-Type` comes from the detected signature. Filename extensions, uploaded media types, SVG, and arbitrary binary content do not control the response type.

`GET /api/v1/shares/{shareId}/preview/svg?path={path}` streams the exact bytes of an `svg` document as `image/svg+xml` under the sandboxed preview CSP, for an `<img>` only. Any file that is not an SVG document receives `415 unsupported_entry`, and one above the render limit `413 preview_too_large`, never a partial document. It takes a download slot like `/preview/image`.

`GET /api/v1/shares/{shareId}/thumbnail?path={path}&size={256|1600}` returns a server-rendered JPEG (opaque) or PNG (with transparency) no larger than `size` on its long edge, with EXIF orientation applied and no metadata. Other sizes receive `400 invalid_thumbnail_size`, files that cannot be thumbnailed `415`, files over the source or decode memory limits `413 thumbnail_too_large`, and a full decode budget `429 busy` with `Retry-After`. The image panel uses the 1600 size for `thumbnailable` documents. Because an `<img>` cannot read a failed response, the client requests the URL once more after an image error to learn the status: `429` shows a retry action, and any other failure falls back to `/preview/image` for `image` documents or explains that a `raw` file has no viewable preview. The application CSP allows only same-origin images, so thumbnails are never converted to `blob:` or `data:` URLs.

`GET /api/v1/shares/{shareId}/open?path={path}` serves a file inline under the sandboxed preview CSP: allowlisted image, PDF, audio, and video signatures with their signature media type, an SVG document within the render limit as `image/svg+xml`, and any other UTF-8 text as `text/plain; charset=utf-8`. Other files receive `415`. It supports one byte range and `If-None-Match` like downloads. The toolbar's **Open in new tab** link (`target="_blank"`, `rel="noopener noreferrer"`) uses it when `openable` is `true`, beside the unchanged **Download** link; the panel's `<audio>` and `<video>` elements use it as their source with `preload="metadata"`. The PDF preview draws only the first page with pdf.js, which fetches this route (with the same `&v=` revision parameter as the media elements) using byte ranges; see [Previews](previews.md#pdf). The full document opens through **Open in new tab**.

These endpoints authenticate and authorize every request. Missing grants and missing content are intentionally indistinguishable. See [Preview security contract](previews.md) for the complete response and isolation requirements.

The client offers source and readable Markdown modes. Its readable mode renders GitHub Flavored Markdown, including tables, task lists, footnotes, alerts, and an allowlisted subset of raw HTML, by walking a detached parsed document into Preact elements; nothing is assigned through `innerHTML`, images are never requested, and only http(s) and mailto links open. [Preview security contract](previews.md) lists the exact rules. Shiki code tokens are likewise rendered as text children. HTML has rendered and source tabs. The panel's new-tab action opens Crabinet's full-window viewer at `/{shareId}/{path}?view=rendered`, which shows the same empty-sandbox iframe; the toolbar's Open in new tab action opens the inert plain-text source through `/open`. Browser history records only validated virtual paths and side/expanded-modal/full-window display mode, never file contents.
