# Filename and metadata search

Search matches filenames, including phrases in double quotes, recursively within a folder, a share, or all shares granted to the signed-in user. The default scope is the current share. Names are matched case insensitively, and queries are compared in Unicode NFC, so a decomposed accent matches its composed form; exact names rank before prefixes, then substring matches. Hidden entries, including files beneath hidden folders, follow the account's hidden-files preference. Trash and Crabinet's internal entries are excluded. Files are not opened to search their contents.

The search field suggests up to eight matches after a 250 ms pause. Arrow keys select a suggestion, Enter opens the selected entry, and Escape dismisses suggestions. Enter without a selected suggestion opens full results. Ctrl+K or Command+K focuses search. Search results retain the existing file preview and offer an action to open the containing folder. Query, scope, pagination, and selected preview are represented in the URL and browser history. Search previews offer read actions; open the containing folder to edit or organize files.

The top bar shows a narrow search field until it is focused or holds a query, then widens to show its scope selector and an icon-only filter button. The filter button opens a panel directly underneath; Escape, the close button, or clicking outside dismisses it. The panel builds the same query syntax as the search field, and the filter button shows how many filters the query applies. Different filter families combine with AND; repeated types or extensions combine with OR. Size filters apply only to regular files, never calculated folder sizes. Type is an extension-based category, not a content inspection or a security classification.

| Example | Meaning |
| --- | --- |
| `invoice` | Filename contains invoice |
| `"annual report"` | Filename contains the phrase |
| `type:pdf` | PDF files |
| `type:image type:video` | Images or videos |
| `type:document` | Text, Markdown, and common Office document extensions |
| `type:code` | Common source and configuration extensions |
| `type:folder` | Folders |
| `type:file` | All regular files |
| `type:other` | Files outside the named categories |
| `ext:pdf ext:docx` | Either extension |
| `size:>10kb` | More than 10,000 bytes |
| `size:>=10mb size:<100mb` | A file size range |
| `modified:>=2026-01-01 modified:<2026-02-01` | January 2026, using UTC midnight boundaries |

Size values are nonnegative integers. Units are case insensitive: B, KB, MB, GB, KiB, MiB, GiB; a number without a unit means bytes. Decimal units use powers of 1,000, binary units powers of 1,024. Comparisons accept `>`, `>=`, `<`, `<=`, and `=`; an omitted comparison means equality. Modified-date comparisons operate against the given date at midnight UTC. Invalid filters, unknown operators, and unfinished quoted phrases return a validation error instead of silently changing meaning. Quote a filename containing a colon to search it literally.

## Index storage and updates

A separate SQLite index defaults to `search.sqlite3` beside `server.database_path`; `server.search_index_path` overrides it, with relative paths resolved from the configuration directory. Its parent must already exist. The index and its `-wal`/`-shm` sidecars must be outside every share, separate from account state, configuration, secrets, and the thumbnail cache. New index files use mode 0600; existing files and sidecars must be owner-only regular files without hard-link aliases or symlinks. Keep the index on local storage suitable for SQLite WAL. It contains filenames and relative paths and needs the same privacy protection as the shares.

Every share is indexed unless `search_enabled = false` in its `[[shares]]` configuration. Changing this setting requires a restart. Startup removes data belonging to removed, disabled, or changed share roots; a root's path and filesystem identity determine whether its previous index can be reused. Queries still check the current user's immutable grants before examining results. SQLite never decides who can access a file.

One background worker indexes every share at startup and checks it again five minutes after its previous full pass began. Capability-based inotify watches report which directories changed. Once a share has been quiet for two seconds, or at the latest ten seconds after the first change, only those directories are listed again, and folders that appeared are indexed recursively. A successful Crabinet mutation schedules a full pass only on a share whose directories are not all watched, at most once every 30 seconds. Notifications are hints: a queue overflow schedules a full pass, and changes made while the process was stopped, missed notifications, and remote filesystem changes are repaired by the periodic pass. Watch limits or unsupported notifications fall back to periodic passes. Ordinary directory browsing does not need to remain open for indexing to work.

Each listed directory is reconciled in its own transaction: new names are inserted, a changed kind, size, or date is updated, unchanged entries are not rewritten, and names no longer present are removed together with everything indexed beneath them. Matches appear as indexing progresses, and a directory that cannot be listed or exceeds the listing bound keeps its previous entries. The worker spends at most two seconds on one share before moving to the next, and an unfinished pass resumes where it stopped, so a large share is eventually covered. Queries use their own read connections and never wait for the indexer. Results are reopened through the existing share capabilities, and current kind, size, and date are checked before returning them. Deleted, linked, unsupported, or unreadable candidates are omitted. Newly added files and changed metadata may remain undiscoverable until indexed; search is eventually consistent, not a filesystem snapshot.

The UI reports indexing until a share's first pass finishes, from a successful Crabinet mutation until the worker has taken in its notifications, and while notified changes are pending, and keeps refreshing suggestions and results meanwhile; the periodic check of a current index is not reported. It also reports incomplete coverage when the last pass, or later refreshes, skipped a directory or hit a bound. The index is disposable: stop Crabinet and remove only this index and its sidecars to rebuild it. An index written by an older Crabinet layout is rebuilt automatically. Account sessions, preferences, and passkeys remain in the original database. Backing up the search index is unnecessary.

## Resource limits and API

`GET /api/v1/search?q=invoice&share=documents&path=reports&showHidden=false&limit=8&offset=0` requires authentication. Omit `share` to search all granted indexed shares; `path` is only valid with a share and includes all descendants. Unknown, disabled, and ungranted specific shares have the same 404 response. A request without a selected share and no granted indexed shares returns an empty result. Responses are private and not cached.

The response contains `entries` (shareId, relative path, name, kind, optional size and RFC 3339 modified time), `indexing`, `incomplete`, and an optional `nextOffset`. Pagination is a best-effort view of a changing index; offsets refer to indexed candidates, so pages may contain fewer matches after live validation. No exact global count is exposed.

| Bound | Limit |
| --- | ---: |
| Indexed entries, across all shares | 200,000 |
| SQLite database pages | 256 MiB, plus transient WAL/SHM overhead |
| SQLite page cache | 2 MiB for indexing, 512 KiB for each of 4 query connections |
| Directory listing | 10,000 inspected entries, including skipped entries |
| Indexing work per share | 2 seconds per round; an unfinished pass resumes |
| Pending directories per pass | 4,096 |
| Inotify watches | At most 4,096, divided among indexed shares |
| Query | 1,024 UTF-8 bytes, 32 terms/filters |
| SQLite query execution | 1 second, checked every 1,000 VM operations |
| Concurrent searches | 4 process-wide, 2 per user |
| Returned candidates per page | 100 maximum; suggestions use 8, full results 50 |
| Pagination offset | 10,000 maximum |
| Authorized shares in one query | 1,024 maximum |

Filesystem calls can block on slow storage; time budgets are checked between operations and do not interrupt a kernel I/O call. Resource or traversal limits produce incomplete coverage rather than claiming exhaustive results. A full disk or database failure retains earlier entries and logs a generic indexing failure for that share. Search can return 429 when its work budget or concurrency limit is exceeded. A larger installation should measure scan duration, index size, and interactive latency before changing these limits.
