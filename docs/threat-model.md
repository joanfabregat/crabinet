# Threat model

## Scope

Crabinet is an authenticated file browser for explicitly mounted filesystem roots. Operators define users, enabled sign-in methods, optional Argon2id password hashes and verified-email OIDC bindings, shares, and per-share grants in an immutable TOML file. The application serves one embedded browser client, stores sessions and passkey state in SQLite, emits audit records to structured logs, and reads or modifies mounted files only through authenticated API operations.

This model covers the application, its OCI image, its configuration and secret mounts, and the browser security boundary. TLS termination, host filesystem administration, container-engine security, backup storage, and the reverse proxy are operator-controlled dependencies.

## Assets

- File contents and metadata inside configured shares.
- Password hashes, session secrets, session records, CSRF tokens, and passkey credentials and user handles.
- Configuration, audit records, and security logs.
- Integrity of read-only shares and authorization grants.
- Availability within the configured CPU, memory, storage, and request limits.
- Browser origin integrity: uploaded content must not act with application authority.

## Trust boundaries

1. The public network to the reverse proxy and application HTTP listener.
2. The browser client to authenticated JSON, upload, download, and preview endpoints.
3. User-controlled virtual paths and content to pre-opened share capabilities.
4. The application process to read-only configuration, secret files, SQLite state, and share mounts.
5. Build dependencies and GitHub Actions to release binaries and OCI images.

Configuration and mounted share roots are operator-trusted at startup. Reverse proxies listed in `server.trusted_proxies` are trusted only to report the connecting client's address, and only for login rate limiting; forwarding headers from any other peer are ignored. Filenames, paths below a share, file contents, HTTP input, cookies, multipart metadata, and authenticated non-administrator users are untrusted.

## Attacker classes

- An unauthenticated remote attacker attempting credential attacks, resource exhaustion, CSRF, or parser abuse.
- A compromised read-only user attempting enumeration or mutation.
- A malicious writer attempting path escape, symlink races, stored active content, or denial of service against other users.
- An attacker with a copied configuration or SQLite database attempting offline password or session recovery.
- A compromised dependency or CI workflow attempting supply-chain modification or credential theft.
- An operator mistake that mounts an unexpectedly broad or writable host directory.

## Security invariants

1. Every filesystem operation begins with an authorized share ID and a validated relative virtual path, and executes relative to a pre-opened capability directory.
2. No request-derived value becomes an ambient absolute filesystem path.
3. Authorization is enforced by the backend for every operation. UI state never grants authority.
4. Missing authorization and missing content are indistinguishable where disclosure would matter.
5. Symlinks and filesystem special files are rejected in v1. Checks occur at the filesystem operation, not only lexically.
6. A globally read-only share remains read-only regardless of user grants and should also be mounted read-only.
7. Passwords are accepted only for verification, never logged or stored. Configuration contains approved Argon2id PHC hashes only.
8. Sessions are opaque, server-side, expiring, revocable, and transported only in protected cookies. State-changing requests require CSRF and same-origin validation.
9. Uploads, text saves, downloads, directory and Trash listings, previews, other request-path blocking filesystem work, event streams, and password verification have explicit concurrency and resource bounds. Each concurrency bound refuses excess work immediately with `429` rather than queueing it, and every one that an authenticated user can fill also has a per-user cap. Request bodies that hold a slot have idle and absolute deadlines.
10. Temporary uploads are never served and completed writes become visible atomically where the filesystem permits it.
11. User files are never exposed by a generic static-file service.
12. Code and text render as inert text. Markdown, including its raw HTML, is rebuilt from a detached parsed document through a tag and attribute allowlist, never through `innerHTML`; it loads no images and opens only http(s) and mailto links, and the application CSP plus script- and stylesheet-free download MIME types back that allowlist up. HTML preview has both iframe and HTTP CSP sandboxes and cannot execute scripts, submit forms, navigate, open popups, use application storage, or contact external origins. The UI loads rendered HTML only in that iframe, including in its full-window new-tab viewer, and the server refuses top-level loads that browsers report through `Sec-Fetch-Dest`, because a CSP sandbox alone does not stop a top-level document navigating itself.
13. Logs, errors, test artifacts, and CI output exclude passwords, hashes, cookies, session IDs, secret contents, and file contents.
14. Release images package the same tested binaries attached to the release; dependency and provenance evidence accompanies releases.
15. Passkey registration requires CSRF proof and a session that signed in within the last 10 minutes. Authentication binds a single-use challenge to the configured HTTPS origin and relying party, requires user verification, and maps the credential to an enabled local user before creating a session.

The concrete path grammar, capability lifecycle, alias policy, platform assumptions, and authorization contract are specified in [Filesystem security boundary](filesystem-security.md). Preview formats, size limits, response headers, and the source-only HTML decision are specified in [Preview security contract](previews.md).

## Threats and controls

| Threat | Primary controls | Verification |
| --- | --- | --- |
| Path traversal and encoding tricks | Typed relative paths, capability directories, component validation | Unit, property, and integration tests; fuzzing; Semgrep and Clippy rules that keep ambient path APIs inside `src/filesystem.rs` |
| Symlink/TOCTOU escape | No-follow directory-relative operations; reject links and special files | Race-oriented temporary-filesystem tests |
| Broken access control | Central grant evaluator; authorization at every handler and filesystem operation | Exhaustive user/share/operation matrix; weekly report-only mutation testing |
| Password cracking | Argon2id with enforced parameters and salts; protected configuration | PHC policy tests and release benchmarks |
| Login denial of service | Per-source limit checked before the shared Argon2 verifier, per-account-and-source limit, bounded concurrent Argon2 operations, client address taken from forwarding headers only for explicitly trusted proxies (right-to-left, falling back to the TCP peer) | Concurrency, username-flood, shared-proxy lockout, and header-spoofing tests |
| Session theft/fixation | Random opaque IDs, hashed server records, rotation, expiry, secure cookies | HTTP integration tests |
| Passkey account confusion or replay | Discoverable credential and user-handle mapping, origin and relying-party checks, user verification, single-use expiring challenges | WebAuthn unit and router tests |
| CSRF | CSRF token plus Origin/Referer validation and SameSite cookies | Cross-origin request tests |
| Stored XSS/active HTML | Inert rendering, sanitizer, CSP sandbox, iframe sandbox | Real-browser hostile fixtures; Semgrep and ESLint rules that reject HTML and script sinks; CodeQL |
| Upload exhaustion | Streaming, request/file/count/quota limits, private per-share staging, bounded non-recursive recovery, cleanup, process-wide and per-user concurrency for uploads (configured, default 4/3) and text saves (4/2), 60-second idle timeout plus an absolute upload deadline (upload size at 64 KiB/s, at least 10 minutes), 60-second text-save body deadline | Multipart failure, staging recovery, stalled and trickling body, and resource tests |
| Read and blocking-pool exhaustion | Process-wide and per-user caps on listings including Trash (16/8), whole-file buffered reads and previews (4/2), streaming downloads (64/8), event streams (64/4), and other request-path blocking filesystem work such as metadata and image opens (64/16); session lookups stay outside these caps | Gate saturation and release tests per gate and per subject |
| Stale event streams | Streams end after 60 seconds and re-check their session every 15 seconds | Sign-out router test |
| Connection exhaustion (slow or idle clients) | Configurable HTTP/1.1 header-read timeout covering new and idle keep-alive connections, configurable process-wide connection cap | TCP-level server tests |
| Header injection/content sniffing | Validated header values, safe disposition encoding, `nosniff` | Response-header tests |
| Dependency or workflow compromise | Lockfiles, dependency review, Semgrep, Trivy, CodeQL, pinned Actions, minimal permissions, actionlint and zizmor, per-architecture image attestations | Pull-request, weekly, and release CI; the release fails unless the index and each architecture image verify |
| Overbroad host access | Explicit mounts, non-root image, read-only rootfs, dropped capabilities | Pull-request and pre-publication release smoke tests run the image with a read-only root, all capabilities dropped, no-new-privileges, and UID 65532, then check readiness, an authenticated listing, the non-root process, and that the image binary matches the release archive; Trivy image and Containerfile scans; operator documentation |

## Deferred risks and non-goals

- Executing uploaded JavaScript requires a separate origin without application cookies and is not supported in v1.
- Public links, anonymous shares, archive extraction, object stores, collaborative editing, and browser ACL administration are not supported in v1.
- Malware scanning is not included initially. Operators must not treat file availability as a malware-safety assertion.
- Physical host compromise, malicious container runtime administrators, and compromised TLS termination are outside the application boundary.

## Security exception process

Any exception to an invariant or scanner finding must be committed, narrowly scoped, name an owner, explain impact and compensating controls, link to a tracking issue, and include an expiry date. Permanent wildcard suppressions are not accepted.

## Backend verification layers

The pull-request gate runs `cargo test --locked --all-targets --all-features`. It includes table-driven policy tests, property tests for path and authorization grammars, assembled-router tests using real login cookies and CSRF middleware, hostile temporary-filesystem fixtures, conditional download/mutation checks, multipart interruption and cleanup checks, and bounded-concurrency tests. Linux-only descriptor and race tests run in the normal Linux CI job. All fixtures use synthetic data under fresh temporary directories.

For a scheduled or manual extended run, use `PROPTEST_CASES=4096 cargo test --locked --release --all-targets --all-features`. The higher property-case count and release-mode race interleavings are deliberately separate from the fast pull-request gate. Regressions must be reduced to synthetic fixtures; test output and saved cases must not contain passwords, cookies, session identifiers, host paths, or user file contents.

Six `cargo-fuzz` targets live under `fuzz/`: `config_toml`, `phc_policy`, `virtual_path`, `multipart`, `markdown_classification`, and `content_disposition`. Run each target from the repository root, for example `cargo fuzz run virtual_path -- -max_total_time=300`, and run the full target list in the weekly extended security job. Pull requests run every target for 20 seconds with the same pinned nightly and check the fuzz lockfile for advisories. The multipart target drives the actual mutation router against a unique synthetic temporary share; the parser/classifier targets call the same production functions behind the opt-in `fuzzing` feature. Corpora and crash artifacts must remain synthetic and must not be committed if they contain machine paths or environment-derived values.

Run the ignored Argon2 sizing benchmark with `cargo test --locked --release benchmark_default_argon2_verification_profile -- --ignored --nocapture` inside the deployment cgroup. For each release candidate, independently record cgroup `memory.peak` for idle, one login, a maximum page listing, upload, download, and preview. Reset the cgroup between scenarios. The supported low-memory starting point remains `auth_max_concurrent = 1`; the container limit must cover idle peak plus the largest accepted Argon2 memory parameter and at least 25% headroom. A non-login scenario fails the resource check if memory grows with full upload/download size instead of the documented stream/preview bound, or if peak memory regresses by more than 10% without an architecture note and updated deployment recommendation.
