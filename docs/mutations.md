# Mutation and upload API

All routes below are under `/api/v1` and require an authenticated session with a grant for the share. Trash listing accepts a read grant; state-changing routes require effective `read-write` access and the authentication middleware's session-bound CSRF verification. Mounting the mutation router without that middleware fails closed with `403`.

Paths are canonical virtual paths relative to one configured share. Absolute paths, dot segments, separators inside names, percent-encoded triplets, non-NFC Unicode, control characters, Windows device names, symbolic links, hard-linked files, and special files are rejected. Reserved internal names (`.crabinet`, legacy `.index-staging`, and the `.index-tmp-` prefix) are rejected in any ASCII letter case. A name that a request creates (a new file or directory, a move or rename destination with a different name, or a non-replacing upload filename) additionally rejects invisible or text-reordering characters: Unicode format characters (`Cf`, such as bidi overrides, zero-width spaces and joiners, and the byte-order mark) and line and paragraph separators (`Zl`, `Zp`). Existing entries with such names stay listed and usable, including moves that keep their name. A move never accepts another share identifier, so cross-share moves are impossible by construction.

## Routes

| Method and route | Body/query | Result |
| --- | --- | --- |
| `POST /shares/{share}/directories` | JSON `{ "path": "folder" }` | Creates one directory; an existing name is `409`. |
| `POST /shares/{share}/files` | JSON `{ "path": "file.txt" }` | Atomically publishes a new empty regular file; an existing name is `409`. |
| `PUT /shares/{share}/text?path=file.txt` | UTF-8 request body plus `If-Match` | Replaces a regular file if its metadata validator is current. |
| `POST /shares/{share}/move` | JSON `{ "source": "a", "destination": "b" }` plus `If-Match` | Renames a file or directory inside one share without replacing the destination. |
| `DELETE /shares/{share}/entry?path=a` | `If-Match` | Moves a file or directory, including a nonempty directory, to the share's Trash and returns a `trashId`. |
| `GET /shares/{share}/trash` | None | Lists published Trash items for users with access to the share. |
| `POST /shares/{share}/trash/{id}/restore` | JSON `{}` or `{ "destination": "other/path" }` | Restores without overwriting. An absent original parent or occupied destination leaves the item in Trash. |
| `DELETE /shares/{share}/trash/{id}` | None | Marks an item for permanent purge and starts bounded cleanup. |
| `POST /shares/{share}/uploads?path=folder` | `multipart/form-data`, file parts only | Streams files to the share's private staging directory and returns `207` with one outcome per file. |

The validator for replace, move, and move-to-Trash is the `ETag` returned by `GET /shares/{share}/metadata?path=...`. Missing, stale, or malformed `If-Match` values produce `409`. Uploads do not overwrite by default. With `replace=true`, each file part must carry its own `If-Match` header; a request-level header is accepted only as a fallback, which is mainly useful for a single-file request. Trash listing is available with read access; restore and purge require effective read-write access and CSRF verification.

## Integrity and resource behavior

Upload chunks are written directly to randomly named files under the writable share's private `.crabinet/staging` directory. The staging directory is created mode `0700`, opened without following links, reserved from the virtual path grammar, and omitted from listings and quota traversal. The server does not buffer a complete upload in memory. Text saves are buffered only up to `max_text_bytes` so UTF-8 can be validated before publication. Multipart requests are bounded by the configured payload limit plus a small capped framing allowance, file count, per-file bytes, aggregate file bytes, a process-wide concurrent-upload limit, a per-user limit of one less (at least one) so one user cannot hold every slot; the default allows four uploads in total and three per user, matching the browser client's three parallel uploads, and an optional share quota. An upload that delivers no new part or chunk for 60 seconds is aborted with `400`, releasing its slot and every unpublished staging file.

Filesystem work runs on the runtime's blocking thread pool, so a slow disk or network filesystem never stalls request handling. Quota checks and publication are serialized per share; mutations of unrelated shares do not wait for each other.

No destination is visible until its complete staged file has been flushed and synced. New files and moves use atomic no-replace renames. Replacements use an atomic exchange, revalidate both sides, and remove the old file only after validation. Staging and target-directory metadata are synced where the filesystem supports directory `fsync`; because the rename or unlink is already committed at that point, a directory `fsync` failure is logged and the mutation still reports success. A cancelled, malformed, oversized, or rejected request drops its capability-scoped staging-file guards and removes every unpublished file. Startup recovery performs one bounded, non-recursive pass over `.crabinet/staging` and removes only reserved `.index-tmp-<128-bit hex>` regular files without following links; it never traverses user content. Replacement cleanup still uses staging; a failed rollback can leave a retained `.index-del-` entry for operator review. Startup recovery never deletes these entries.

Trash lives in private `.crabinet/trash`. Each item has an opaque-ID payload and a JSON sidecar recording its original share-relative path, kind, deleting subject, deletion time, and expiration. A pending sidecar is synced before the source is moved, then marked live after the move; startup reconciliation completes interrupted publications. Restore uses an atomic no-replace rename through validated share handles. Purge marks a sidecar before bounded, no-follow deletion, so startup and later GC passes can resume it. Trash content counts toward share quota. The default retention is 30 days, configurable with `server.trash_retention_days`; a bounded pass starts with the server and runs about daily.

Atomic rename requires staging and destination directories to be on the same filesystem. A writable share's staging directory is therefore inside its root. Writes into, and moves across, a nested mount on a different device are rejected with `400` and the stable `cross_device` audit reason rather than copied or published non-atomically.

A writable share must be owned by one Crabinet process or pod at a time. Multiple replicas pointing at the same writable directory are not supported because each process owns the private staging namespace and its recovery. Read-only shares create no staging directory and may use separate read-only replicas.

Multipart files are all staged before publication, so a parsing or request-limit failure publishes none of them. Publication is intentionally not a multi-file transaction: the `207` response reports `created`, `replaced`, `conflict`, `quota_exceeded`, or `error` for each file. A later file failing does not roll back earlier successful files.

Successful and rejected mutations emit structured audit events containing the subject, share ID, operation, virtual path when appropriate, outcome, and stable reason. Every rejection inside a handler is audited, including invalid paths or names, stale or missing `If-Match` (`stale_validator`), missing entries, quota, busy upload slots, idle uploads, and cross-device writes. Requests rejected before the handler runs (missing session, CSRF proof, or a malformed JSON, query, or multipart envelope) are not audited here. File contents, credentials, host paths, session values, and CSRF tokens are never logged.

Replacement creates a new inode and does not preserve the prior file's timestamps, ownership overrides, extended attributes, or mode beyond the service process's configured umask. Operators should treat files with metadata requirements outside that model as read-only shares.
