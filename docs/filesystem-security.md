# Filesystem security boundary

## Capability lifecycle

Each configured share is opened exactly once by `ShareFs::open`. The root path must be absolute and comes only from operator-trusted startup configuration. The root's parent directory is opened with ambient authority, then the final root component is opened with `open_dir_nofollow`; request-time code never receives the ambient path and cannot recover one from `ShareFs`.

All later operations start from the retained `cap_std::fs::Dir`. Intermediate components are opened one at a time with `cap_fs_ext::DirExt::open_dir_nofollow`. Final files use `OpenOptionsFollowExt::follow(FollowSymlinks::No)` and are classified from the opened handle before bytes are exchanged. File opens are nonblocking so a FIFO cannot stall a worker while it is being rejected. Directory creation is followed by a no-follow reopen. This handle-oriented walk prevents a renamed ancestor or a symlink replacement from redirecting an operation outside its share.

The production support target for v1 is Linux. On Unix, regular files with a link count other than one are rejected so a hard link cannot alias a file outside the share. Other Unix targets retain these controls but are not release-tested in v1. Non-Unix targets fail closed when classifying entries because the implementation does not yet provide an equivalent hard-link alias guarantee.

## Request path grammar

HTTP and routing code must decode a path exactly once before calling `VirtualPath::parse`; it must not decode the resulting components again. An explicit `VirtualPath::root()` represents the share root. An empty user-supplied path is invalid.

Each component is UTF-8 and NFC-normalized, at most 255 bytes, and excludes:

- empty, `.` and `..` components;
- slash, backslash, NUL, control characters, colon, and trailing dot or space;
- percent triplets such as `%2f`, which could be decoded inconsistently by another layer;
- Windows device names, including superscript-digit `COM` and `LPT` variants.

The complete virtual path is at most 4096 bytes. Existing non-UTF-8 or non-NFC directory entries are rejected rather than lossily renamed or displayed. These restrictions intentionally trade access to a small set of legitimate host filenames for consistent security semantics across proxies, URL decoders, browsers, Linux, macOS, and Windows clients.

## Authorization contract

Only `AuthorizedShare` exposes request-time operations. It can be created only from a grant whose `ShareId` exactly matches the opened share. Missing and wrong-share grants both return `AccessDenied`. Read-only grants permit listing and reads; read-write grants additionally permit mutations. `GlobalPolicy::read_only` always reduces a read-write grant to read-only.

Operations accept one authorized share and never accept an ambient source or destination path. Consequently, cross-share rename and move cannot be expressed through this API. A later mutation layer must preserve this constraint and must not expose raw `Dir` handles.

The core intentionally has no existing-file replacement primitive. Truncating a visible file in place can expose partial content after an interrupted or concurrent write. The upload and mutation layer must introduce a separately reviewed atomic replacement abstraction using a same-directory temporary file, bounded streaming, synchronization, no-follow validation, and an atomic final rename where supported.

## Entry policy and errors

Only directories and single-link regular files are supported. Symbolic links, sockets, FIFOs, devices, invalid UTF-8 names, non-NFC names, and hard-linked regular files are rejected. Directory listings fail closed if any unsupported entry is encountered, ensuring later UI actions cannot accidentally weaken the entry policy.

`FsError` exposes only stable categories. It never contains a configured host path, an OS error string, a filename, or file content. HTTP handlers may map these codes to status values but must not attach the underlying operating-system error to a response. Detailed operational diagnostics, if added, must be server-side and must still avoid configured root paths and user filenames unless explicitly enabled by the operator.

## Race and trust assumptions

The no-follow checks are part of the filesystem open operation, not lexical pre-checks. An opened directory or file handle remains bound to the same object if an ancestor is renamed. Creation uses exclusive `create_new`; an attacker winning the name first causes a conflict or rejection instead of overwrite.

The configured root and the host account controlling mounts are trusted at startup. A host administrator or container-runtime administrator who can replace mounts, inject already-open descriptors, or directly mutate files concurrently is outside the application boundary. Read-only shares should additionally be mounted read-only so the kernel enforces defense in depth.

The application does not expose hard-link, symlink, archive extraction, or cross-share move operations. Adding any of them requires a security design update and new race-oriented tests before implementation.

## Required verification

Tests cover traversal and separator inputs, encoded percent triplets, Windows prefixes and devices, NFC normalization, boundary lengths, invalid UTF-8 host entries, root and nested links, final-component replacement races, special files, hard-link aliases, overlapping roots, bounded reads, and the complete missing/read/read-write/global-read-only grant matrix.
