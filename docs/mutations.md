# Mutation and upload API

All routes below are under `/api/v1`. They require an authenticated session with an effective `read-write` grant for the share. State-changing requests also require the authentication middleware to validate its session-bound CSRF token and insert `CsrfVerified`; mounting the router without that middleware fails closed with `403`.

Paths are canonical virtual paths relative to one configured share. Absolute paths, dot segments, separators inside names, percent-encoded triplets, non-NFC Unicode, control characters, Windows device names, symbolic links, hard-linked files, and special files are rejected. Reserved internal names (`.index-staging` and the `.index-tmp-` prefix) are rejected in any ASCII letter case. A name that a request creates (a new file or directory, a move or rename destination with a different name, or a non-replacing upload filename) additionally rejects invisible or text-reordering characters: Unicode format characters (`Cf`, such as bidi overrides, zero-width spaces and joiners, and the byte-order mark) and line and paragraph separators (`Zl`, `Zp`). Existing entries with such names stay listed and usable, including moves that keep their name. A move never accepts another share identifier, so cross-share moves are impossible by construction.

## Routes

| Method and route | Body/query | Result |
| --- | --- | --- |
| `POST /shares/{share}/directories` | JSON `{ "path": "folder" }` | Creates one directory; an existing name is `409`. |
| `POST /shares/{share}/files` | JSON `{ "path": "file.txt" }` | Atomically publishes a new empty regular file; an existing name is `409`. |
| `PUT /shares/{share}/text?path=file.txt` | UTF-8 request body plus `If-Match` | Replaces a regular file if its metadata validator is current. |
| `POST /shares/{share}/move` | JSON `{ "source": "a", "destination": "b" }` plus `If-Match` | Renames a file or directory inside one share without replacing the destination. |
| `DELETE /shares/{share}/entry?path=a` | `If-Match` | Deletes a regular file or an empty directory. Recursive deletion is not supported. |
| `POST /shares/{share}/uploads?path=folder` | `multipart/form-data`, file parts only | Streams files to the share's private staging directory and returns `207` with one outcome per file. |

The validator for replace, move, and delete is the `ETag` returned by `GET /shares/{share}/metadata?path=...`. Missing, stale, or malformed `If-Match` values produce `409`. Uploads do not overwrite by default. With `replace=true`, each file part must carry its own `If-Match` header; a request-level header is accepted only as a fallback, which is mainly useful for a single-file request.

## Integrity and resource behavior

Upload chunks are written directly to randomly named files under the writable share's private `.index-staging` directory. The staging directory is created mode `0700`, opened without following links, reserved from the virtual path grammar, and omitted from listings and quota traversal. The server does not buffer a complete upload in memory. Text saves are buffered only up to `max_text_bytes` so UTF-8 can be validated before publication. Multipart requests are bounded by the configured payload limit plus a small capped framing allowance, file count, per-file bytes, aggregate file bytes, a process-wide concurrent-upload limit, a per-user limit of one less (at least one) so one user cannot hold every slot; the default allows four uploads in total and three per user, matching the browser client's three parallel uploads, and an optional share quota. An upload that delivers no new part or chunk for 60 seconds is aborted with `400`, releasing its slot and every unpublished staging file.

Filesystem work runs on the runtime's blocking thread pool, so a slow disk or network filesystem never stalls request handling. Quota checks and publication are serialized per share; mutations of unrelated shares do not wait for each other.

No destination is visible until its complete staged file has been flushed and synced. New files and moves use atomic no-replace renames. Replacements use an atomic exchange, revalidate both sides, and remove the old file only after validation. Staging and target-directory metadata are synced where the filesystem supports directory `fsync`; because the rename or unlink is already committed at that point, a directory `fsync` failure is logged and the mutation still reports success. A cancelled, malformed, oversized, or rejected request drops its capability-scoped staging-file guards and removes every unpublished file. Startup recovery performs one bounded, non-recursive pass over `.index-staging` and removes only reserved `.index-tmp-<128-bit hex>` regular files without following links; it never traverses user content. Deletes move the entry into staging under a separate `.index-del-` name before removing it. If a replacement, move, or delete cannot roll back after a failed validation, the request returns `500`, the affected data is left in place (for a replacement or delete, inside `.index-staging`), and an error is logged without paths. Startup recovery never removes `.index-del-` entries and logs an error when any remain, so an operator can restore or discard them.

Atomic rename requires staging and destination directories to be on the same filesystem. A writable share's staging directory is therefore inside its root. Writes into, and moves across, a nested mount on a different device are rejected with `400` and the stable `cross_device` audit reason rather than copied or published non-atomically.

A writable share must be owned by one Crabinet process or pod at a time. Multiple replicas pointing at the same writable directory are not supported because each process owns the private staging namespace and its recovery. Read-only shares create no staging directory and may use separate read-only replicas.

Multipart files are all staged before publication, so a parsing or request-limit failure publishes none of them. Publication is intentionally not a multi-file transaction: the `207` response reports `created`, `replaced`, `conflict`, `quota_exceeded`, or `error` for each file. A later file failing does not roll back earlier successful files.

Successful and rejected mutations emit structured audit events containing the subject, share ID, operation, virtual path when appropriate, outcome, and stable reason. Every rejection inside a handler is audited, including invalid paths or names, stale or missing `If-Match` (`stale_validator`), missing entries, quota, busy upload slots, idle uploads, and cross-device writes. Requests rejected before the handler runs (missing session, CSRF proof, or a malformed JSON, query, or multipart envelope) are not audited here. File contents, credentials, host paths, session values, and CSRF tokens are never logged.

Replacement creates a new inode and does not preserve the prior file's timestamps, ownership overrides, extended attributes, or mode beyond the service process's configured umask. Operators should treat files with metadata requirements outside that model as read-only shares.
