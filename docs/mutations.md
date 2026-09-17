# Mutation and upload API

All routes below are under `/api/v1`. They require an authenticated session with an effective `read-write` grant for the share. State-changing requests also require the authentication middleware to validate its session-bound CSRF token and insert `CsrfVerified`; mounting the router without that middleware fails closed with `403`.

Paths are canonical virtual paths relative to one configured share. Absolute paths, dot segments, separators inside names, percent-encoded triplets, non-NFC Unicode, control characters, Windows device names, symbolic links, hard-linked files, and special files are rejected. A move never accepts another share identifier, so cross-share moves are impossible by construction.

## Routes

| Method and route | Body/query | Result |
| --- | --- | --- |
| `POST /shares/{share}/directories` | JSON `{ "path": "folder" }` | Creates one directory; an existing name is `409`. |
| `POST /shares/{share}/files` | JSON `{ "path": "file.txt" }` | Atomically publishes a new empty regular file; an existing name is `409`. |
| `PUT /shares/{share}/text?path=file.txt` | UTF-8 request body plus `If-Match` | Replaces a regular file if its metadata validator is current. |
| `POST /shares/{share}/move` | JSON `{ "source": "a", "destination": "b" }` plus `If-Match` | Renames a file or directory inside one share without replacing the destination. |
| `DELETE /shares/{share}/entry?path=a` | `If-Match` | Deletes a regular file or an empty directory. Recursive deletion is not supported. |
| `POST /shares/{share}/uploads?path=folder` | `multipart/form-data`, file parts only | Streams files to sibling temporary files and returns `207` with one outcome per file. |

The validator for replace, move, and delete is the `ETag` returned by `GET /shares/{share}/metadata?path=...`. Missing, stale, or malformed `If-Match` values produce `409`. Uploads do not overwrite by default. With `replace=true`, each file part must carry its own `If-Match` header; a request-level header is accepted only as a fallback, which is mainly useful for a single-file request.

## Integrity and resource behavior

Upload chunks are written directly to randomly named temporary files in the destination directory. The server does not buffer a complete upload in memory. Text saves are buffered only up to `max_text_bytes` so UTF-8 can be validated before publication. Multipart requests are bounded by the configured payload limit plus a small capped framing allowance, file count, per-file bytes, aggregate file bytes, a concurrent-upload semaphore, and an optional share quota.

No destination is visible until its complete temporary file has been flushed and synced. New files and moves use atomic no-replace renames. Replacements use an atomic exchange, revalidate both sides, and remove the old file only after validation. Target-directory metadata is synced where the filesystem supports directory `fsync`. A cancelled, malformed, oversized, or rejected request drops its capability-scoped temporary-file guards and removes every unpublished temporary file. Startup recovery removes reserved `.index-tmp-<128-bit hex>` regular files left by a terminated process without following links.

A writable share must be owned by one Index process or pod at a time. Multiple replicas pointing at the same writable directory are not supported because each process performs startup recovery of the reserved temporary namespace. Read-only replicas may use separate read-only mounts.

Multipart files are all staged before publication, so a parsing or request-limit failure publishes none of them. Publication is intentionally not a multi-file transaction: the `207` response reports `created`, `replaced`, `conflict`, `quota_exceeded`, or `error` for each file. A later file failing does not roll back earlier successful files.

Successful and rejected mutations emit structured audit events containing the subject, share ID, operation, virtual path when appropriate, outcome, and stable reason. File contents, credentials, host paths, session values, and CSRF tokens are never logged.

Replacement creates a new inode and does not preserve the prior file's timestamps, ownership overrides, extended attributes, or mode beyond the service process's configured umask. Operators should treat files with metadata requirements outside that model as read-only shares.
