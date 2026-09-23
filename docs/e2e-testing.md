# Browser end-to-end tests

The Playwright suite runs the release-profile `crabinet` binary with the embedded production frontend. Its server wrapper copies synthetic shares into a unique temporary directory, starts a fresh SQLite session store, and removes the state when Playwright stops. The fixtures contain no credentials or private files, so retained failure traces, screenshots, and videos contain only test data.

## Run locally

Build the production frontend and binary, then run the suite from `web`:

```console
npm run build
cargo build --locked --release
cd web && npm run test:e2e
```

On the dev VM these commands must run through the repository's constrained Node, Rust, and Playwright container workflows. The Playwright image tag must match the locked `@playwright/test` version.

`npm run test:e2e` is the single test command after the production artifact exists. It covers desktop and narrow/mobile Chromium with one worker so state and logs remain deterministic. CI builds the artifact first and uploads the HTML report, trace, screenshot, and video directory on failure.

The suite covers login/logout and cookie attributes, session loss, grant and share isolation, read-only UI and API enforcement, browsing, direct URLs, history, keyboard focus, responsive layout, viewport-filling preview mode, automated accessibility checks, code/Markdown/image previews, hostile rendered HTML in both the empty-sandbox iframe and a CSP-sandboxed top-level tab, inert source in a top-level tab, and event-driven out-of-band directory refresh. Production-backed mutation flows cover create, edit, concurrent-save conflicts, move/rename without overwriting, entry-specific deletion confirmation, preview closure after deletion, non-empty directory refusal, native drag-and-drop, the keyboard file picker, upload limits and partial results, explicit replacement, progress, cancellation, disconnect retry, and cancellation when history changes the upload destination.

To regenerate the deterministic README screenshot after an intentional UI change, build the release binary as above and run:

```console
cd web && npm run screenshot:readme
```
