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
4. The application process to read-only configuration, owner-only secret files, SQLite state, and share mounts.
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
9. Uploads, text saves, downloads, folder and selection archives, directory and Trash listings, previews, other request-path blocking filesystem work, event streams, and password verification have explicit concurrency and resource bounds. Each concurrency bound refuses excess work immediately with `429` rather than queueing it, except that an image thumbnail waits up to about two seconds for its share of the decode memory budget, and a request for a thumbnail another request is already rendering waits for that result, holding no memory reservation; every concurrency bound that an authenticated user can fill also has a per-user cap. Request bodies that hold a slot have idle and absolute deadlines.
10. Temporary uploads are never served and completed writes become visible atomically where the filesystem permits it.
11. User files are never exposed by a generic static-file service.
12. Code and text render as inert text. Markdown, including its raw HTML, is rebuilt from a detached parsed document through a tag and attribute allowlist, never through `innerHTML`; it loads no images and opens only http(s) and mailto links, and the application CSP plus script- and stylesheet-free download MIME types back that allowlist up. HTML preview has both iframe and HTTP CSP sandboxes and cannot execute scripts, submit forms, navigate, open popups, use application storage, or contact external origins. The UI loads rendered HTML only in that iframe, including in its full-window new-tab viewer, and the server refuses top-level loads that browsers report through `Sec-Fetch-Dest`, because a CSP sandbox alone does not stop a top-level document navigating itself. Files open inline in a new tab (`/open`) only when their bytes match an allowlisted raster image, PDF, audio, or video signature, served with that signature's media type, as a strictly content-detected SVG document within the preview limit, served as `image/svg+xml`, or as UTF-8 text served as `text/plain`; the filename and uploaded `Content-Type` never choose the type, and every inline response, PDF and SVG included, carries the same sandboxed deny-by-default CSP with no exception. An SVG is drawn in the panel only through an `<img>`, where browsers run no script, load no external resource, and allow no interaction; as a top-level document, the CSP sandbox without `allow-scripts` and `default-src 'none'` stop scripts, event handlers, `javascript:` URLs, external loads, forms, and popups. A link the reader clicks in a top-level SVG can still navigate the tab, as in a PDF; no SVG navigates on its own. Everything else is download-only. Image thumbnails are re-encoded by the server as JPEG or PNG without metadata and served under the same sandboxed CSP; RAW files are shown only through them, never inline.
13. Logs, errors, test artifacts, and CI output exclude passwords, hashes, cookies, session IDs, secret contents, and file contents.
14. Release images package the same tested binaries attached to the release; dependency and provenance evidence accompanies releases.
15. Passkey registration requires CSRF proof and a session that signed in within the last 10 minutes. Authentication binds a single-use challenge to the configured HTTPS origin and relying party, requires user verification, and maps the credential to an enabled local user before creating a session.

The concrete path grammar, capability lifecycle, alias policy, platform assumptions, and authorization contract are specified in [Filesystem security boundary](filesystem-security.md). Preview formats, size limits, response headers, and the source-only HTML decision are specified in [Preview security contract](previews.md).

## Threats and controls

| Threat | Primary controls | Verification |
| --- | --- | --- |
| Path traversal and encoding tricks | Typed relative paths, capability directories, component validation | Unit, property, and integration tests; fuzzing; Semgrep and Clippy rules that keep ambient path APIs inside `src/filesystem.rs` |
| Symlink/TOCTOU escape | No-follow directory-relative operations; reject links and special files | Race-oriented temporary-filesystem tests |
| Broken access control | Central grant evaluator; authorization at every handler and filesystem operation | Exhaustive user/share/operation matrix; route-enumeration test that sends every route in the inventory without a session (`401`) and to an ungranted share (the same `404` as a missing one); weekly report-only mutation testing |
| Password cracking | Argon2id with enforced parameters and salts; protected configuration | PHC policy tests and release benchmarks |
| Login denial of service | Per-source limit checked before the shared Argon2 verifier and before a passkey sign-in ceremony is stored (one budget per source for both), per-account-and-source limit, bounded concurrent Argon2 operations, client address taken from forwarding headers only for explicitly trusted proxies (right-to-left, falling back to the TCP peer) | Concurrency, username-flood, passkey-start flood, shared-proxy lockout, and header-spoofing tests |
| Session theft/fixation | Random opaque IDs, hashed server records, rotation, expiry, secure cookies | HTTP integration tests |
| Passkey account confusion or replay | Discoverable credential and user-handle mapping, origin and relying-party checks, user verification, single-use expiring challenges | WebAuthn unit and router tests |
| CSRF | CSRF token plus Origin/Referer validation and SameSite cookies | Cross-origin request tests; the route-enumeration test refuses every state-changing route without a CSRF token, with a wrong one, cross-origin, cross-site, or without Origin and Referer |
| Stored XSS/active HTML | Inert rendering, sanitizer, CSP sandbox, iframe sandbox, signature-only allowlist for inline opens with markup served as `text/plain` | Real-browser hostile fixtures; signature tests with SVG/HTML named `.pdf`, PDF polyglots, and AVIF/MP4 brand confusion; per-type inline-open header tests; Semgrep and ESLint rules that reject HTML and script sinks; CodeQL |
| Active SVG content | SVG recognized only from content (UTF-8, unprefixed `<svg>` root with the exact SVG default namespace, no internal DTD subset or other processing instruction), only within the preview limit, never from the extension; served only as `image/svg+xml` under the sandboxed deny-by-default CSP (no `allow-scripts`, `default-src 'none'`, `form-action 'none'`) with `nosniff`, `Cross-Origin-Resource-Policy: same-origin`, and `no-store`; the panel uses only `<img>`; a head of a larger SVG is never rendered | Strict-detection unit tests (namespace, prefix, doctype, internal subset, processing instruction, cut tag); route tests for `/preview/svg` and `/open` headers, `413` above the limit, and `415` for non-SVG; a Playwright hostile fixture (script, `onload`/`onclick`/`onbegin`, `javascript:` link, external images, styles, fonts, `<use>`, filters, `<foreignObject>` with meta refresh, form, iframe, and popup link) in the `<img>` and as a top-level tab asserting no dialog, script effect, storage, cookie, popup, navigation, form submission, or request leaving the browser, run in Chromium in CI and checked in Firefox |
| Large text previews | A file above `max_preview_size` returns a head cut from the 64 KiB header already read (at most 64 KiB and 1,000 lines), so memory stays bounded whatever the file size; binary and invalid UTF-8 are rejected on that header first; HTML endpoints refuse heads; heads cannot be edited | Unit tests for every cut rule and a sparse 1 GiB file; route tests for `415` on oversized binary and `413` from both HTML endpoints; a Playwright test on a 312 kB log |
| Upload exhaustion | Streaming, request/file/count/quota limits, private per-share staging, bounded non-recursive recovery, cleanup, process-wide and per-user concurrency for uploads (configured, default 4/3) and text saves (4/2), 60-second idle timeout plus an absolute upload deadline (upload size at 64 KiB/s, at least 10 minutes), 60-second text-save body deadline | Multipart failure, staging recovery, stalled and trickling body, and resource tests; the resource-limit registry covers uploads and text saves |
| Read and blocking-pool exhaustion | Process-wide and per-user caps on listings including Trash (16/8), whole-file buffered reads and previews (4/2), streaming downloads, image previews, and inline opens, held for the body's lifetime (64/8), folder and selection archives, held from the bounded pre-stream walk to the end of the body (4/2), with one walk budget per request across every selected entry and at most 1,000 selected paths in a 256 KiB query, event streams (64/4), and other request-path blocking filesystem work such as metadata lookups (64/16); session lookups stay outside these caps | Gate saturation and release tests per gate and per subject; selection-archive tests for limits shared across selected entries, the path and query caps, mixed parents, overlaps, and duplicates; a resource-limit registry that drives every gated route in the route inventory to `429` with its gate full, process-wide and for one subject, then admits it after release, and requires every other route to be explicitly exempt |
| Image decompression bombs and decode memory exhaustion | Thumbnails decode only PNG, JPEG, GIF, WebP, and JPEG previews embedded in TIFF-based RAW files, with pure-Rust decoders (no C image libraries); a 100 MiB source cap and the 100-megapixel cap; each decode reserves its header-derived peak estimate from one process-wide budget (`max_image_decode_memory`) before starting, answers `413` when the estimate exceeds the budget and `429` after a short wait, and checks decoder-reported dimensions against the parsed header; the TIFF walk bounds directories, entries, depth, and candidates and detects loops; thumbnails are cached only after authorization, under keyed-hash names in an owner-only directory | Unit tests for budget accounting on success, error, and panic, `413` and `429` with a tiny budget, lying headers, and hostile TIFF structures; fuzz targets for the RAW preview extractor and for header estimates plus decoding under tiny budgets; cache isolation tests across shares and after a revoked grant |
| Stale event streams | Streams end after 60 seconds and re-check their session every 15 seconds | Sign-out router test |
| Connection exhaustion (slow or idle clients) | Configurable HTTP/1.1 header-read timeout covering new and idle keep-alive connections, configurable process-wide connection cap | TCP-level server tests |
| Header injection/content sniffing | Validated header values, safe disposition encoding, `nosniff`, JSON error envelopes for malformed requests | Response-header tests |
| Undetected or repudiated attacks | Audit events for sign-in outcomes, logout, expired or revoked sessions, refused share access, and mutations, keyed digests for unknown account names, server-generated request IDs | Log-capture tests asserting events and the absence of secrets, including an upload, read, preview, download, and save flow whose logs must omit the file contents, session cookie, and CSRF token |
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

Axum cannot list a router's routes, so one route inventory in the `src/app.rs` tests classifies every `(method, path)` the application serves by access (public, session, or share), required proof (none, same-origin, or CSRF), and resource bound (a named gate, or an explicit exemption with its reason). A test scans every `.route(` call outside test modules under `src/` and fails when the inventory and the routers differ, so a new route cannot merge unclassified. Three tests consume the inventory:

- The route-enumeration test sends every route through the real session and CSRF middleware. It requires `401` without a session, the same non-disclosing `404` for an ungranted share as for a missing one, and `403` for every state change without a CSRF token, with a wrong one, cross-origin, cross-site, or without Origin and Referer.
- The resource-limit registry fills each gated route's gate process-wide, then for one subject only. It requires `429` with `Retry-After` (`busy`, or `rate_limited` for event streams), that another subject is still admitted, and that the route is admitted again once the slots are released.
- The log-redaction test uploads, reads, previews, downloads, and saves a file carrying a distinctive marker, then asserts that the captured logs record the operations but never the marker, the session cookie, or the CSRF token. The capture subscriber records the `info` level, the production default.

For a scheduled or manual extended run, use `PROPTEST_CASES=4096 cargo test --locked --release --all-targets --all-features`. The higher property-case count and release-mode race interleavings are deliberately separate from the fast pull-request gate. Regressions must be reduced to synthetic fixtures; test output and saved cases must not contain passwords, cookies, session identifiers, host paths, or user file contents.

Seven `cargo-fuzz` targets live under `fuzz/`: `config_toml`, `phc_policy`, `virtual_path`, `multipart`, `markdown_classification`, `content_disposition`, and `zip_archive`. Run each target from the repository root, for example `cargo fuzz run virtual_path -- -max_total_time=300`, and run the full target list in the weekly extended security job. Pull requests run every target for 20 seconds with the same pinned nightly and check the fuzz lockfile for advisories. The multipart target drives the actual mutation router against a unique synthetic temporary share; the parser/classifier targets call the same production functions behind the opt-in `fuzzing` feature, and `virtual_path` also parses its input as an archive query and checks that an accepted selection names distinct entries of one directory within the path cap. `zip_archive` streams fuzzer-chosen folder entries through the production ZIP writer and checks the result with an independent reader and bitwise CRC-32, and checks layouts with arbitrary declared sizes so the ZIP64 records are covered. Corpora and crash artifacts must remain synthetic and must not be committed if they contain machine paths or environment-derived values.

Run the ignored Argon2 sizing benchmark with `cargo test --locked --release benchmark_default_argon2_verification_profile -- --ignored --nocapture` inside the deployment cgroup. For each release candidate, independently record cgroup `memory.peak` for idle, one login, a maximum page listing, upload, download, and preview. Reset the cgroup between scenarios. The supported low-memory starting point remains `auth_max_concurrent = 1`; the container limit must cover idle peak plus the largest accepted Argon2 memory parameter and at least 25% headroom. A non-login scenario fails the resource check if memory grows with full upload/download size instead of the documented stream/preview bound, or if peak memory regresses by more than 10% without an architecture note and updated deployment recommendation.
