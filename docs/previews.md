# Preview security contract

## V1 behavior

Preview input is untrusted. Every HTTP preview handler must extract the authenticated identity, resolve the requested share grant again for that request, and pass only an `AuthorizedShare` plus a validated `VirtualPath` to `preview::load`. The preview module cannot accept an ambient filesystem path. Missing grants and missing entries use the same public `404` response.

`preview::load` reads a bounded 64 KiB header from the opened handle and classifies it by signature first (see [Signatures](#signatures)). Raster images, PDF, audio, and video are streamed types: the JSON preview returns only their metadata, and their bytes are served from the file handle by `/preview/image` and `/open`, never buffered. The configured preview limit (`max_preview_size`) therefore bounds only previews that buffer the whole file: text, code, Markdown, and HTML. A PDF, image, or media file of any size up to the download cap previews; images keep their pixel cap.

The configured preview limit must be greater than zero and no more than the process-wide 16 MiB ceiling. After a file fails every streamed signature, the implementation compares the opened file's metadata with that limit before allocating, reads at most `limit + 1` bytes to detect a concurrent growth race, and rejects an oversized file instead of returning a partial document. Successful responses therefore always report `truncated: false`. Previews that buffer a document share a process-wide limit of four concurrent requests with the text-read API; the file is read on the blocking thread pool, and further requests receive `429` with code `busy` and `Retry-After`. The JSON `/preview` request takes that slot even for a streamed type, because it reads the header; the `/preview/image` and `/open` streams are not buffered and take a download slot instead.

Text previews require valid UTF-8 without binary control characters. Invalid UTF-8, NUL bytes, other binary controls, directories, symbolic links, special files, and hard-linked aliases are rejected. Filename extensions supply only fixed syntax-language hints and never select an executable response type. Streamed types are classified from their bytes rather than their filename or an uploaded `Content-Type`.

Every preview document carries `openable`. It is `true` for images, PDF, and every text-like kind, which the UI then offers as **Open in new tab** beside **Download**. It is `false` for audio and video: they stream from `/open` into the panel's `<audio>` and `<video>` elements, but a browser cannot play them as a top-level document under the sandboxed policy (see [Inline open](#inline-open)).

## Signatures

Only these signatures select a streamed type, checked in this order on the bounded header:

| Kind | Signature | Media type |
| --- | --- | --- |
| `image` | PNG, GIF, JPEG, WebP (`RIFF….WEBP`), AVIF (`ftyp` major brand `avif`), with safe known dimensions | `image/png`, `image/gif`, `image/jpeg`, `image/webp`, `image/avif` |
| `pdf` | `%PDF-` at byte 0, or within the first 1024 bytes as browsers accept when the prefix is not clean UTF-8 text | `application/pdf` |
| `video` / `audio` | ISO-BMFF: a complete leading `ftyp` box whose major brand is `isom`, `iso2`, `iso4`–`iso6`, `mp41`, `mp42`, `avc1`, `dash`, `M4V `, or `MSNV` (video), or `M4A `/`M4B ` (audio), and whose major or compatible brands name no HEIF/AVIF image brand | `video/mp4`, `audio/mp4` |
| `video` | EBML magic `1A 45 DF A3` with a `webm` or `matroska` DocType in the EBML header | `video/webm` |
| `audio` / `video` | `OggS` version 0; a Theora first packet is video, anything else audio | `audio/ogg`, `video/ogg` |
| `audio` | `RIFF….WAVE` | `audio/wav` |
| `audio` | `fLaC` followed by a 34-byte STREAMINFO block | `audio/flac` |
| `audio` | an ID3v2 header (version 2–4, syncsafe size), or two consecutive valid MPEG Layer III frame headers | `audio/mpeg` |

The late-`%PDF-` rule is narrower than the browsers' so a text file that mentions the marker near its start stays inert `text/plain`; a marker after the first kilobyte never makes a PDF. QuickTime, 3GP, HEIF, ADTS AAC, and any other container get no streamed type. A single MPEG frame sync is too weak on its own, so a second frame must follow. SVG, HTML, and XML are never a streamed type: they are text.

## Text, code, and Markdown

The JSON endpoint returns `{ kind, source, language, size, truncated }`. Source text remains a JSON string and is never interpolated into application HTML. Markdown is returned as `markdown_source`: the server does not render it, resolve embeds, fetch URLs, or interpret raw HTML.

The frontend renders GitHub Flavored Markdown in the application DOM, the way GitHub does, and never through `innerHTML`. markdown-it, with raw HTML and URL autolinking enabled and the footnote plugin, produces an HTML string that also carries the file's own raw HTML. Crabinet adds heading ids, task-list checkboxes, and GitHub alerts (`> [!NOTE]`) as markdown-it core rules. The HTML string is parsed with `DOMParser` into a detached document, which runs no scripts and loads no resources, and `safe-markdown.tsx` walks that document into Preact elements:

- Only a fixed allowlist of HTML-namespace elements is recreated. Scripts, styles, frames, objects, embeds, media, templates, form controls other than task checkboxes, SVG, and MathML are dropped with their content. Any other element, including `form` and `button`, is unwrapped to its children.
- Only `id`, `title`, `lang`, `dir`, a validated `align`, clamped numeric table and list attributes, `open` on `details`, and `datetime` on `time` are carried over. Event handlers, `class`, and `style` never are; table column alignment is recognized only in markdown-it's exact `text-align` form and applied as a CSSOM property.
- Every `id` is prefixed with `user-content-` so a document cannot shadow application elements. In-document `#fragment` links scroll to the prefixed target without routing.
- Links open only for `http:`, `https:`, and `mailto:` URLs, in a new tab with `rel="noopener noreferrer nofollow"`. Any other scheme and every relative link render as inert text.
- Images are never loaded. They render as a placeholder showing their alt text, which also keeps remote images from revealing who opened a file.
- Fenced code with a supported language goes through the same Shiki highlighter as code previews; other fences are text. Raw HTML nesting beyond 64 levels is flattened to text, and documents larger than 1 MiB are not rendered.

The application CSP (`default-src 'self'` without `'unsafe-inline'`) is the backstop if this allowlist is ever wrong: inline scripts, event handlers, and style attributes cannot run, and downloads never carry a script or stylesheet MIME type (see [Browse API](browse-api.md)). The parser is loaded on demand when a Markdown file is opened. A source tab always exposes the exact returned text.

Code highlighting uses Shiki with a fixed language allowlist and dynamically loaded grammars. Highlighted tokens are rendered as Preact text children; generated or uploaded HTML is never assigned through `innerHTML`.

## HTML

The dedicated HTML-source endpoint intentionally uses `Content-Type: text/plain; charset=utf-8`. It returns the exact validated UTF-8 source and does not parse or escape it into an HTML wrapper. Opening this endpoint in an iframe or a new tab therefore remains inert.

The rendered endpoint uses `Content-Type: text/html; charset=utf-8`. The frontend loads it only in an iframe with an empty `sandbox` attribute: in the preview panel, and in a full-window viewer at `/{shareId}/{path}?view=rendered` that the panel's new-tab action opens. That viewer is a Crabinet page showing the file name, a link back to the folder, and the same sandboxed iframe filling the window. The response independently applies a CSP sandbox with `default-src 'none'`, allows only inline styles and embedded `data:` images, and blocks base-URL changes, form submissions, and ancestor origins other than self. No iframe sandbox tokens are granted: scripts, event handlers, application storage, same-origin access, forms, popups, top navigation, and external network requests remain unavailable. The rendered view shows layout and safe CSS, not an executable web application.

A CSP sandbox does not stop a top-level document from navigating itself, and browsers do not enforce `navigate-to`, so a rendered page opened directly in a tab could send the reader to another site from a Crabinet URL with a plain link or a `<meta http-equiv="refresh">`. The UI therefore never opens the rendered endpoint as a top-level document. The server also refuses it: when a request carries `Sec-Fetch-Dest` with any value other than `iframe`, such as `document` for a tab, the route answers `403` with a plain-text notice under the same preview headers, before authorizing the share or reading the file. Clients that send no `Sec-Fetch-Dest` header receive the rendered document under the CSP sandbox as before.

Every preview response adds:

- `Content-Security-Policy: sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; navigate-to 'none'` for rendered HTML, with the same or stricter deny-by-default policy for other previews;
- `X-Content-Type-Options: nosniff`;
- `Referrer-Policy: no-referrer`;
- `Cache-Control: no-store, private`;
- a restrictive `Permissions-Policy`, `Cross-Origin-Resource-Policy: same-origin`, and `X-Frame-Options: SAMEORIGIN`;
- the fixed `Content-Disposition: inline`, without a user-controlled filename.

The frontend must still use an empty iframe `sandbox` attribute. This is intentional defense in depth rather than permission to enable any sandbox token.

Uploaded JavaScript execution and live external resources are not supported in v1. Adding either requires a separate origin that receives no application cookies, has no access to application storage, and cannot reach authenticated application APIs. A same-origin `allow-scripts` or `allow-same-origin` exception is forbidden.

## Images

`GET /api/v1/shares/{shareId}/preview/image?path=...` authenticates and authorizes the request, opens the file through the same share capability, applies the download size cap rather than the buffered preview limit, and validates a bounded header for a supported raster signature and safe known dimensions. The file then streams from that already-validated handle in fixed-size chunks rather than being buffered in Rust memory. Because the stream holds an open file, each image takes a download slot (64 across the process, 8 per user, shared with downloads as described in the [browse API](browse-api.md)) before the file is opened and keeps it until the response body completes or is dropped; further requests receive `429` with code `busy`. The response chooses its media type from the signature, never from an extension or uploaded `Content-Type`, and includes the exact metadata length plus the same no-sniffing, no-referrer, private no-store, permissions, and same-origin resource policies. SVG is intentionally excluded because it is active document content.

## PDF

The preview panel shows only the first page of a PDF, drawn to a `<canvas>` by pdf.js in the browser (see the [architecture decision](architecture-decisions.md#pdf-first-page-with-pdfjs-full-document-in-the-browser-viewer)). The server never parses or renders PDFs; it only classifies the signature and streams bytes from `/open`. pdf.js is loaded on demand as its own chunk the first time a PDF is previewed, so the main bundle does not carry it, and it parses the document in a same-origin module worker that is terminated once the page is drawn or the preview closes.

pdf.js runs under the unchanged application CSP (`default-src 'self'`, with neither `'unsafe-eval'` nor `'wasm-unsafe-eval'`) with these options:

- `useWasm: false`: the JavaScript JPEG 2000 and JBIG2 decoders replace the WebAssembly ones, which the CSP would block and which are not shipped.
- `annotationMode: DISABLE` and `enableXfa: false`: no annotations, links, form widgets, or XFA forms are drawn or made interactive, and PDF JavaScript is never run.
- Range loading: `disableRange: false` with `disableStream: true` and `disableAutoFetch: true`, so pdf.js requests only the byte ranges page 1 needs instead of the whole file. This relies on `/open` answering with `Accept-Ranges: bytes`, an exact `Content-Length`, no `Content-Encoding`, and `206` responses with `Content-Range`, which Rust tests assert.
- Bounded output: the canvas backing store is capped at 16 megapixels (the render scale follows the panel width and device pixel ratio up to that cap), and embedded images larger than 50 megapixels are skipped.
- CMaps, the Foxit standard fonts, and the non-WebAssembly decoders load by name from `assets/pdfjs-<version>/`, which the build copies unchanged from the package; other fonts fall back to system fonts.

A password-protected, malformed, or unloadable PDF shows an error in the panel instead of a page, and **Open in new tab** and **Download** remain. The canvas is exposed as an image labelled "First page of {file name}".

The full document opens through **Open in new tab**, which loads `/open` as a top-level document in the browser's built-in viewer under the same sandboxed preview CSP as every other inline type (see [Why PDF needs no CSP exception](#why-pdf-needs-no-csp-exception)). That viewer provides search, zoom, and printing; Crabinet never frames it.

## Inline open

Every file keeps **Download**, an attachment under `default-src 'none'; sandbox`. `GET /api/v1/shares/{shareId}/open?path=...` is the second, inline representation, offered only for bytes a browser displays without running script on this origin. It authenticates and authorizes the request like the other preview routes (a fresh grant resolution, a validated `VirtualPath`, and the same non-disclosing `404`), takes a download slot before opening the file, reads the bounded header, and serves:

- a streamed type from [Signatures](#signatures) with that signature's media type;
- otherwise UTF-8 text, checked with the text-preview rules on the 64 KiB header (a character cut by the header bound is tolerated, any other invalid sequence is not), always as `text/plain; charset=utf-8`. HTML, SVG, XML, and every other markup are therefore only ever served as inert source;
- otherwise nothing: `415` with `binary_file`, `invalid_utf8`, or `unsupported_entry`, as `/preview` reports them.

The body streams from the handle that was classified, so a path swapped after the check cannot change what is served. The route shares the download implementation for validators and ranges: a weak `ETag`, `If-None-Match` (`304`), one byte range (`206` with `Content-Range`, `416` when unsatisfiable), and the same weak-validator `If-Range` fallback, so PDF viewers and media elements can seek. It is bounded by the download size cap, not by `max_preview_size`. The response carries a fixed `Content-Disposition: inline` without a user-controlled filename and every header listed under [HTML](#html), with the same sandboxed deny-by-default CSP for every type, PDF included.

### Why PDF needs no CSP exception

The design first assumed that Chrome's and Firefox's built-in PDF viewers refuse to render in a sandboxed document, which would have forced dropping `sandbox` for PDF. That was checked before shipping and is not the case for a top-level document: Chromium 153 (Playwright's full Chromium build in new headless mode) and Firefox 155 (Playwright's build with pdf.js enabled) both rendered a test PDF opened as a top-level tab under `sandbox; default-src 'none'; …`, exactly as without a CSP, and also under `default-src 'none'` with or without `object-src`. PDF is therefore served under the same sandboxed policy as everything else. Embedding PDFs in frames was not tested; the UI never frames this route. If a supported browser is later found that will not render a top-level PDF under the sandbox, the narrowest fallback is to drop only `sandbox` for `application/pdf` while keeping `default-src 'none'`, and that change must be recorded here and in the threat model.

### Audio and video

A browser plays a top-level audio or video URL by wrapping it in a generated media document whose player refetches the URL. Under `default-src 'none'` that refetch is blocked as `media-src`, and under `sandbox` the document's origin is opaque, so the refetch is refused by CORS (Chromium 153; Playwright's Firefox downloaded media instead of displaying it). Playing media in a new tab would require dropping `sandbox` and allowing `media-src 'self'`, which this route does not do. Audio and video previews instead stream from `/open` into `<audio controls>` and `<video controls>` elements in the preview panel with `preload="metadata"` and no autoplay; as subresources of the application page, governed by its `default-src 'self'` CSP, they play under the sandboxed response policy. Their preview documents report `openable: false`, so the UI shows no new-tab action for them.

## Hostile fixtures

Tests keep representative payloads for scripts, event handlers, `javascript:` links, forms, top navigation, popups, meta refresh, external beacons, and SVG/script combinations. Response tests assert that source stays plain text, rendered HTML receives the complete sandbox policy and is served only to frames, and raster media types come only from validated signatures. Signature tests cover SVG and HTML named `.pdf` (inert text), a PDF named `.txt` (a PDF), a `%PDF-` polyglot beyond the first kilobyte and a text file that mentions the marker (both text), AVIF and HEIF brands that must not become MP4 video, a lone MPEG frame sync, and text that starts like an ID3, Ogg, or FLAC signature. Inline-open tests assert per-type media types, the sandboxed CSP on every type including PDF, ranges and conditional requests, `415` for binary and unknown containers, and the non-disclosing `404`. Browser tests assert the rendered iframe has an empty `sandbox` attribute, that hostile content cannot create storage, dialogs, navigation, or completed external responses, and that a link or meta refresh in the full-window viewer leaves the tab on the application origin.
