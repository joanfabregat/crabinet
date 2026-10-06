# Browser end-to-end tests

The Playwright suite runs the release-profile `crabinet` binary with the embedded production frontend. Its server wrapper copies synthetic shares into a unique temporary directory, starts a fresh SQLite session store, and removes the state when Playwright stops. The fixtures contain no credentials or private files, so retained failure traces, screenshots, and videos contain only test data.

## Run locally

Build the production frontend and binary, then run the suite from `web`:

```console
npm run build
cargo build --locked --release
cd web && npm run test:e2e
```

Run these commands in locked-down containers, as [CONTRIBUTING.md](../CONTRIBUTING.md) describes. The Playwright image tag must match the locked `@playwright/test` version. In a rootless container that cannot `chroot`, Firefox's content processes crash on start (`Sandbox: chroot: EPERM`, then `Target crashed`); for such a local run only, set `MOZ_DISABLE_CONTENT_SANDBOX=1`, `MOZ_DISABLE_RDD_SANDBOX=1`, `MOZ_DISABLE_GMP_SANDBOX=1`, `MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1`, and `MOZ_DISABLE_UTILITY_SANDBOX=1`, and give the container a larger `/dev/shm` (for example 2 GiB). CI runs Firefox with its sandbox.

`npm run test:e2e` is the single test command after the production artifact exists. It runs every project with one worker so state and logs remain deterministic; `npm run test:e2e -- --project "*-webkit"` runs one engine's projects. CI builds the artifact first and uploads the HTML report, trace, screenshot, and video directory on failure.

## Browser projects

| Project | Engine | Viewport and input |
| --- | --- | --- |
| `desktop-chromium` | Chromium | 1440×960, mouse |
| `mobile-chromium` | Chromium | 390×844, touch, mobile viewport |
| `desktop-webkit` | WebKit | 1440×960, mouse, desktop Safari user agent |
| `ipad-webkit` | WebKit | 1194×834 (iPad Pro 11 in landscape), touch, mobile viewport, iPad user agent |
| `desktop-firefox` | Firefox | 1440×960, mouse |
| `oidc-chromium`, `oidc-webkit`, `oidc-firefox` | Chromium, WebKit, Firefox | 1280×720, mouse; only `e2e/oidc.spec.ts`, against the OIDC server (see [OpenID Connect sign-in](#openid-connect-sign-in)) |

Each engine has its own production server with fresh fixtures, on consecutive ports from `CRABINET_E2E_PORT` (Chromium, then WebKit, then Firefox), and the projects of one engine share it. Playwright's WebKit on Linux does not keep the `Secure`, `__Host-` session cookie over plain HTTP, even on `localhost`, so the WebKit server sits behind `e2e/tls-proxy.ts`, a Node built-ins TLS proxy that forwards requests unchanged (including `Host`) the way a production reverse proxy does, with a self-signed certificate that `run-server.sh` creates with `openssl` for each run; the WebKit projects ignore its issuer. Suites that change server state, such as the mutation flows, and the layout matrix that opens its own browser contexts run once per engine, in its desktop project. Against one external server (`CRABINET_E2E_BASE_URL`), the mutation flows run only in `desktop-chromium` and the OIDC projects are not defined.

CI runs one Browser E2E job per engine in parallel, each installing only its browser and running that engine's projects, its `oidc-` project included, so a slower engine never delays or cancels Chromium's result. Chromium keeps the `Browser E2E` check name; the others report as `Browser E2E (WebKit)` and `Browser E2E (Firefox)`.

The WebKit projects run Playwright's WebKit build for Linux, not Apple's Safari. They share Safari's engine (layout, CSS, DOM, JavaScript, cookies, and form and focus behavior), so they catch most Safari- and iPad-only layout and scripting bugs, and the iPad project emulates its viewport, touch input, and coarse pointer. They do not represent Apple's media stack (Linux WebKit plays media through GStreamer, so codec support differs), HEIC decoding (Apple's image decoders are absent, so HEIC falls back as it does in Chromium and Firefox), iPadOS gestures, the on-screen keyboard and its viewport resizing, or Safari's Intelligent Tracking Prevention. Tests of those keep their assertions engine-neutral: the HEIC test accepts either the decoded image or the download fallback.

The suite covers login/logout and cookie attributes, session loss, grant and share isolation, read-only UI and API enforcement, browsing, direct URLs, history, keyboard focus, responsive layout, viewport-filling preview mode, automated accessibility checks, code/Markdown/image previews, folder ZIP downloads, row selection with click and Shift-click, a selection downloaded as one ZIP without a wrapping folder and moved to Trash in bulk, the pdf.js first-page PDF preview without CSP violations, hostile rendered HTML in the empty-sandbox iframe of both the preview panel and the full-window new-tab viewer, a link and meta refresh that cannot move that tab off the application origin, refusal of rendered HTML as a top-level document, inert source in a top-level tab, and event-driven out-of-band directory refresh. Production-backed mutation flows cover create, edit, concurrent-save conflicts, move/rename without overwriting, direct moves to Trash, restoring files and non-empty folders, preview closure after deletion, native drag-and-drop, the keyboard file picker, upload limits and partial results, explicit replacement, progress, cancellation, disconnect retry, and cancellation when history changes the upload destination.

## OpenID Connect sign-in

`e2e/oidc.spec.ts` signs in through a real browser redirect to a fake provider, `e2e/fake-oidc.ts`, and runs only in the `oidc-*` projects, against a fourth production server on the port after Firefox's. Its server enables OIDC beside password sign-in, so the other suites keep their own servers and sign-in page unchanged. Its callback must be HTTPS, so it is always behind the TLS proxy, and the Crabinet origin (`https://localhost`) and the provider (`https://127.0.0.1`, 200 ports higher) are different sites, as in production.

For each run `run-server.sh` creates, with `openssl`, a test CA and a provider certificate it signs for `127.0.0.1` and `localhost`, deletes the CA's key, and writes a random client secret. It starts the provider first, because Crabinet reads discovery at startup, then appends the `[auth.oidc]` section with the provider as issuer, the CA as `auth.oidc.ca_file`, and the proxied callback as `redirect_uri`. Crabinet therefore trusts the provider only through `ca_file`; the browsers ignore certificate errors, because the browser's trust is not what is under test. Nothing is committed: no certificate, key, or secret lives in the repository.

The provider uses Node built-ins only and implements just what Crabinet uses: discovery, a JWKS, the authorization endpoint, and the token endpoint. It refuses, so that the test fails, an authorization request with a missing, repeated, or unexpected parameter, another `client_id` or `redirect_uri`, a `response_type` other than `code`, a scope without `openid` and `email`, a malformed `state` or `nonce`, or a PKCE challenge that is not S256, and a token request without `client_secret_basic` credentials, with another `redirect_uri`, or with a verifier that does not match the challenge. Codes are single use and expire after a minute. ID tokens are RS256-signed with the issuer, the client as audience and `azp`, the nonce, `iat`, `exp`, the subject, and a verified email; Crabinet's own tests cover ES256. A consent page offers three fixed identities, `reader` (whose `oidc_subject` the fixture configuration binds), `writer`, and `stranger` (no account), and a Cancel button that returns `error=access_denied`.

The tests cover returning to a deep link, the start folder at the root with and without a saved one, tampered `return_to` values (protocol-relative, absolute, encoded, API, and dot-segment targets) that land on the app root without a request leaving the origin, signing in again on the same page after the session cookie disappears, a provider error and a callback whose `state` belongs to another attempt or is forged (each answered `401` on the callback, with no redirect and no session), an unknown identity, and password sign-in on the same server. They do not cover a real provider's behavior, such as Google's consent screens, account chooser, token lifetimes, key rotation, or UserInfo (the fake puts the verified email in the ID token, so Crabinet never calls UserInfo), nor provider sign-out through the end-session endpoint.

To regenerate the deterministic README screenshot after an intentional UI change, build the release binary as above and run:

```console
cd web && npm run screenshot:readme
```

## Archive compatibility

The ZIP writer's own tests read every archive back with an independent reader in `src/zip.rs`, which also checks each entry's header fields against what strict extractors expect: version needed to extract 4.5 only for entries with ZIP64 fields and 2.0 otherwise, identical in the local and central headers; general-purpose flags of exactly bit 11 (UTF-8 names) for folders and bits 11 and 3 (data descriptor) for files; a data descriptor with its optional `0x08074b50` signature after every file; and a ZIP64 data descriptor only after a local header that carries a ZIP64 extra field (APPNOTE 4.3.9).

The Rust CI job also checks real archives from the download endpoint with three independent extractors. The test `browse::tests::archives_for_external_extractors` writes them when `CRABINET_ZIP_SAMPLES_DIR` names a directory, together with the tree each must extract to, and `.github/scripts/check-zip-extractors.sh` lists, integrity-tests, and extracts each one, comparing the result byte for byte, names and empty folders included:

| Archive | Covers |
| --- | --- |
| `folder` | A folder archive mixing deflated text, a stored binary, a stored short file, an empty folder, and a UTF-8 (non-ASCII) name in a subfolder |
| `single-file` | One deflated file, with no wrapping folder |
| `single-utf8-file` | One deflated file with a UTF-8 name, with no wrapping folder |
| `selection` | A selection of an empty folder, a folder, and a stored file, each at the top level |

| Extractor | Package (Ubuntu 26.04) | Commands |
| --- | --- | --- |
| libarchive | `libarchive-tools` | `bsdtar -tvf`, `bsdtar -xf` |
| Info-ZIP | `unzip` | `unzip -t`, `unzip` |
| 7-Zip | `7zip` | `7z t`, `7z x` |

To run the check locally, in containers as above: run the test with `CRABINET_ZIP_SAMPLES_DIR` set to an empty directory, then run the script with that directory where the three extractors are installed. macOS Archive Utility and Windows Explorer cannot run in CI; the header rules above are the ones they are known to depend on.
