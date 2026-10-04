# Architecture decisions

## Rust, Axum, and Tokio

Rust provides explicit error handling, predictable memory behavior, and capability-oriented filesystem libraries for the application’s main security boundary. Axum and Tokio supply maintained HTTP and asynchronous I/O primitives without a second runtime service.

## Preact and Vite

Preact provides the component model needed for uploads, navigation, and previews with a small browser footprint. Vite and TypeScript are build-time dependencies only. Compiled assets are embedded in the Rust executable.

## Immutable TOML configuration

Users, shares, grants, limits, and secret-file references are operator configuration. One versioned TOML file avoids ambiguous precedence. Only the configuration path has a CLI/environment bootstrap override. Changes require restart in v1.

## Filesystem data and SQLite runtime state

Files remain normal files in explicitly mounted roots. SQLite stores server-side sessions, per-user start-folder and display preferences, and passkey credentials and user handles, while structured audit events go to standard output with the rest of the application logs. This avoids a database service while keeping runtime state separate from immutable configuration.

## Argon2id

Passwords are one-way hashed with Argon2id v19 and unique salts in PHC format. The application enforces lower and upper parameter bounds and limits concurrent verification to preserve availability.

## Capability-scoped filesystem access

Each trusted configured share is opened once as a capability directory. Request paths remain validated relative paths and never regain ambient filesystem authority. Symlinks and special files are rejected in v1.

## One binary and one container process

The frontend is compiled before Rust and embedded in the executable. Releases provide that binary directly and package the identical bytes in a minimal, non-root OCI image. Production requires no Node process, static server, Redis, or external database.

## Open in a new tab versus download

Every file can be downloaded, and downloads are always `Content-Disposition: attachment`. A file the browser can display without running script on the application origin also gets an inline route and an "Open in new tab" action. The inline allowlist is decided from the file's bytes, never its extension or uploaded type: validated raster images (PNG, JPEG, GIF, WebP, AVIF), PDF, and UTF-8 text served as `text/plain`. HTML, SVG, and XML are active documents on the application origin, so they are only ever served inline as `text/plain` source; rendered HTML keeps its sandboxed preview. Inline responses stream from the validated file handle with a fixed `inline` disposition and the deny-by-default preview headers, including a CSP `sandbox` for every type. Common audio and video containers are served by the same route but play only in the preview panel's native players: a browser plays a media file opened as a tab by fetching it again from the document it builds around it, and under `sandbox` that document has an opaque origin, so the fetch fails. Media therefore has no "Open in new tab" action rather than a CSP exception; the panel player has its own fullscreen control. `max_preview_size` bounds only previews that are buffered in server memory (text, code, Markdown, and HTML source); streamed types are not bound by it, and images keep their pixel cap.

## PDF: first page with pdf.js, full document in the browser viewer

The preview panel shows only the first page of a PDF, drawn to a canvas by pdf.js, which is loaded on demand so the main bundle does not grow. pdf.js runs without `eval`, PDF JavaScript, forms, or XFA, and within the application CSP. The browser's built-in viewer cannot be limited to one page or sized as a preview, so it serves only the "Open in new tab" action, where users get search, zoom, and printing. Server-side rendering with pdfium or MuPDF was rejected: it would parse untrusted PDFs in C on the server, and MuPDF is AGPL. Chromium's and Firefox's viewers run outside the page's origin, as a browser extension and as privileged pdf.js respectively, so they render a PDF served with the same sandboxed preview CSP as every other inline type; no exception is needed. If a supported browser's viewer ever refuses a sandboxed document, the fallback is to drop only `sandbox` for PDF and keep `default-src 'none'` and the other preview headers.

## Server-side image thumbnails within a decode memory budget

The preview panel shows a server-generated thumbnail instead of the original image, so large photos cost neither bandwidth nor browser memory. Memory depends on decoded pixels, not file size, so each decode path reserves its estimated peak before starting: baseline JPEG decodes directly at ½, ¼, or ⅛ scale and PNG is reduced row by row, while progressive JPEG, WebP, AVIF, and GIF hold a full frame. Reservations come from one process-wide budget, `max_image_decode_memory`; a request that would exceed the available budget waits briefly and then receives `429 busy`, and an image whose estimate alone exceeds the budget is not thumbnailed. With memory bounded by that budget, the file byte cap for images rises to 100 MiB. RAW files are thumbnailed from the JPEG preview embedded in TIFF-based containers (DNG, NEF, ARW, CR2, PEF, ORF) through the same scaled JPEG path; CR3 and RAF need their own extractors and come later. Demosaicing RAW data is rejected, because the Rust implementations are LGPL and slow, and HEIC is rejected, because the only decoder is libheif, in C. Decoders are pure Rust and fuzzed, including the TIFF preview parser. Thumbnails are cached on disk at a configured path, keyed by share, path, size, and modification time, with a configured size limit and oldest-first eviction.
