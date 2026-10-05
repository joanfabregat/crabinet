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
      "kind": "directory",
      "folderSize": { "size": 1234567, "complete": true }
    },
    {
      "name": "drafts",
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

The cursor contains no host path. Its HMAC binds the authenticated subject, effective access grant, share ID, virtual path, offset, and a fingerprint of the sorted listing structure (each entry's kind, name, and file identity). Tampering, use by another user or grant, use for another directory, or an entry being added, removed, renamed, or replaced between pages rejects the cursor with `409`; clients should restart from the first page. Size and modification-time changes, such as a file still being written, do not invalidate the cursor. `nextCursor` is omitted on the final page. File entries include `size`; directory entries omit it. A directory entry carries `folderSize` (`size` and `complete`, as from the [folder-size route](#folder-size)) only when the server's folder-size cache already holds a fresh size for it; the listing never walks a folder, takes no folder-size gate slot, and omits `folderSize` for every other folder and whenever `server.folder_sizes` is `false`. The cache is read only after the listing's own grant check, the same rule the folder-size route follows. Modification time remains optional in the frontend contract and is omitted until a lightweight RFC 3339 formatter is part of the reviewed dependency set.

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

`GET /api/v1/shares/{shareId}/download?path=relative/path` streams from the already validated regular-file handle. It never buffers the whole file. Each stream is capped by the configured maximum file size and fixed read chunk size, and dropping the response cancels the stream and closes the handle. At most 64 downloads stream concurrently across the process and 8 per authenticated user, counting streamed image previews (`/preview/image`) and inline opens (`/open`); a slot is held until the response body completes or is dropped, not merely until headers are sent, and further requests receive `429` with code `busy` and `Retry-After`. Eight per user covers a few parallel downloads plus a media player's overlapping range requests while preventing one user from exhausting file descriptors.

The endpoint supports one RFC-style byte range (`start-end`, `start-`, or `-suffix`), returns `206` with `Content-Range` when applicable, and returns `416` with `Content-Range: bytes */{length}` only for an unsatisfiable range (a first byte at or beyond the end, or `bytes=-0`). As RFC 9110 permits, a syntactically invalid range (including an inverted range or a number with a sign), another range unit, or a multi-range request is ignored and the complete representation is returned with `200`; multiple ranges are intentionally unsupported. `If-None-Match` produces `304`. Download ETags are weak validators derived from file identity, nanosecond modification time, size, share, and virtual path; an `If-Range` request therefore falls back to a complete `200` response as required for weak validators.

Downloads include a safe ASCII fallback plus RFC 5987 UTF-8 filename in `Content-Disposition`. Every file, including raw HTML and SVG, is an attachment. Responses also set `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`, `Accept-Ranges: bytes`, an explicit MIME type, ETag, and content length. The MIME type comes from the file extension, except that JavaScript, CSS, and WebAssembly types are replaced by `application/octet-stream`. An attachment disposition does not stop `<script src>` or `<link rel="stylesheet">` from loading a same-origin URL, so this, together with `nosniff`, keeps the application CSP's `'self'` sources from covering user files.

## Folder archive

`GET /api/v1/shares/{shareId}/archive?path=relative/folder` streams a folder and everything beneath it as a ZIP archive; an absent or empty `path` archives the share root. Any grant on the share, read or read-write, may archive it. The archive's top-level entry is the folder's name, or the share ID for the share root, and the attachment is named after it with a `.zip` suffix.

Before the response starts, the server walks the folder through the share capability with the listing's entry policy: links, special files, hard-link aliases, invalid names, and Crabinet's internal entries are omitted, and every scanned entry counts toward the limit, omitted or not. A folder that exceeds a limit (the sum of file sizes above the download maximum, more scanned entries than the archive entry maximum, or more than 4 MiB of relative path names) returns `413` (`too_large`); an entry deeper than the 64-component limit returns `400` (`path_too_deep`); a path that names nothing returns `404`, and a path that names a file archives that file alone (see [selection archives](#selection-archives)). No archive bytes are produced for a refused folder.

Entries are stored uncompressed, in depth-first order with each directory's children sorted by name and every directory, including empty ones, present as its own entry. Names are UTF-8 (general-purpose flag bit 11), so an extractor sees the same canonical components the browse API returns; the grammar rules out `..`, absolute names, and backslashes. File modes are fixed (`0644` for files, `0755` for directories), and times are the modification times in UTC, both as MS-DOS fields and an extended timestamp. ZIP64 fields appear only where an entry, an offset, or the entry count overflows the classic fields. Because the layout is fixed before streaming, the response carries the archive's exact `Content-Length`.

Each file is reopened through the capability with a no-follow open only when its turn comes, and only one file is open at a time. If a file was removed, replaced by a link or special file, or changed size since the walk, the server ends the response body with an error instead of finishing it. Against the announced `Content-Length` the client then sees a failed transfer, never a complete-looking archive with different contents. A file rewritten in place without a size change is read as it is at that moment, as with a single-file download. Archives do not support `Range`, `If-None-Match`, or ETags.

At most 4 archives run concurrently across the process and 2 per authenticated user; a slot is held from the walk until the response body completes or is dropped, and further requests receive `429` with code `busy` and `Retry-After`. Memory per archive is bounded by the walk (at most the entry maximum and 4 MiB of names, held twice while the layout is built) plus one read chunk, independent of the total archive size. Responses set `Content-Type: application/zip`, the same `Content-Disposition` encoding as downloads, `X-Content-Type-Options: nosniff`, and `Content-Security-Policy: default-src 'none'; sandbox`.

The browser client first requests the archive with `fetch`, cancels it once the response headers show it was admitted, and then hands the same URL to the browser as a download. A refusal is shown in the app instead of replacing the page with a JSON error. The extra request repeats the walk once.

Every browse response, including share discovery, listings, metadata, folder sizes, text, downloads, and archives, sets `Cache-Control: no-store, private` so authenticated content does not remain in the browser disk cache after sign-out. ETags remain available for explicit `If-None-Match`, `If-Range`, and mutation `If-Match` requests.

### Selection archives

The same route archives a selection when `path` names a file or repeats: `GET /api/v1/shares/{shareId}/archive?path=reports/a.pdf&path=reports/2024`. Each value is decoded once and parsed with the virtual path grammar, like every other `path` parameter; other parameters are ignored. One empty or absent `path` is still the share root, and one `path` naming a folder is still the folder archive above. Otherwise the archive has no wrapping folder: every selected entry sits at the top level, a file as `name` and a folder as `name/` followed by its contents, in name order. The attachment is named after the selected file for a single file (`a.pdf.zip`), and after the selection's directory for several entries (`reports.zip`, or the share ID at the share root).

Every selected path must have the same parent directory, so a selection cannot overlap itself (a folder together with an entry inside it) and its top-level names cannot collide; mixed parents, a duplicate path, the share root inside a selection, or an invalid path return `400` (`invalid_request`). A query string longer than 256 KiB or naming more than 1,000 paths returns `413` (`too_large`) before any path is parsed. Reverse proxies often cap the request line well below that (8 KiB is a common default), which bounds a selection of long names first; such a proxy answers `414`, and the client shows a generic archive error. A missing selected path, or one naming a link, special file, or hard-link alias, returns the same `404` as a missing folder, so a selection discloses nothing that single requests would not. One walk budget covers the whole selection: each selected entry counts as one scanned entry, and file sizes, entry counts, and name bytes (each name including its selected top-level component) accumulate across all selected entries against the same limits as a folder, with the same depth limit. The same archive gate applies, and files are reopened and checked while streaming exactly as for a folder.

## Folder size

`GET /api/v1/shares/{shareId}/folder-size?path=relative/folder` returns the total size of the files beneath one folder; an absent or empty `path` measures the share root. Any grant on the share, read or read-write, may ask. The listing never walks a folder: it carries a folder's size only when this route's cache already holds a fresh one (see [directory listing](#directory-listing)), so a client asks here for the other folders it shows.

```json
{
  "shareId": "documents",
  "path": "reports",
  "size": 1234567,
  "complete": true
}
```

`size` is the sum of the file lengths counted, in bytes. The walk uses the [folder archive](#folder-archive)'s entry policy through the share capability: links are never followed, and links, special files, hard-link aliases, invalid names, and Crabinet's internal entries (including Trash) are not counted, while hidden files are. Each walk stops after 200,000 scanned entries or 2 seconds, whichever comes first. A walk cut short, or one that skipped a subfolder it could not read or that lies below the 64-component depth limit, returns what it counted with `complete: false`; `size` is then a lower bound. Only the folder itself must exist and be readable: a missing path, a file, a link, an ungranted share, and an unreadable folder return the same `404` as the listing, and an invalid path returns `400`.

Walks run on the blocking pool behind their own gate: at most 8 across the process and 4 per authenticated user, refused beyond it with `429` (`busy`) and `Retry-After`. Results are cached in memory for 60 seconds, keyed by share and folder and shared by every user granted the share, with at most 2,048 entries; the grant is checked on every request before the cache is read, and a cached answer takes no gate slot. A successful mutation in a share forgets that share's cached sizes. While a [directory event stream](frontend-api-contract.md#directory-browsing) is open, each change its watch reports forgets the size of the changed entry and everything beneath it, and of the watched folder and each of its ancestors. A change made outside Crabinet that no open stream observes, such as one deeper than the watched folder, shows after the cached size expires. When `server.folder_sizes` is `false`, the route returns `404` with code `feature_disabled` to every signed-in user, before the share is checked.

## Default resource limits

| Limit | Default |
| --- | ---: |
| Directory page | 100 entries |
| Maximum requested page | 200 entries |
| Maximum directory scan | 10,000 entries |
| UTF-8 text read | 1 MiB |
| Download, and the sum of file sizes in one folder or selection archive | 1 GiB |
| Folder or selection archive scan | 10,000 entries |
| Folder or selection archive names | 4 MiB |
| Paths in one selection archive | 1,000 |
| Selection archive query string | 256 KiB |
| Streaming read chunk | 64 KiB |
| Folder-size walk | 200,000 scanned entries or 2 seconds |
| Cached folder sizes | 2,048 entries for 60 seconds |

All values except the archive name, selection path, query-string, and folder-size limits, which are fixed, are startup configuration inputs through `BrowseLimits`; invalid zero or internally inconsistent limits prevent browse-state construction. Startup must also provide a non-zero 32-byte cursor HMAC secret from the authenticated application configuration; it is never accepted from a request.
