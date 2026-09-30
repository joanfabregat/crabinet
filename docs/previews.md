# Preview security contract

## V1 behavior

Preview input is untrusted. Every HTTP preview handler must extract the authenticated identity, resolve the requested share grant again for that request, and pass only an `AuthorizedShare` plus a validated `VirtualPath` to `preview::load`. The preview module cannot accept an ambient filesystem path. Missing grants and missing entries use the same public `404` response.

The configured preview limit must be greater than zero and no more than the process-wide 16 MiB ceiling. The filesystem implementation compares the opened file's metadata with that limit before allocating, reads at most `limit + 1` bytes to detect a concurrent growth race, and rejects an oversized file instead of returning a partial document. Successful responses therefore always report `truncated: false`. Previews that buffer a document (text, code, Markdown, and HTML) share a process-wide limit of four concurrent requests with the text-read API; the file is read on the blocking thread pool, and further requests receive `429` with code `busy` and `Retry-After`. The `/preview/image` stream is not buffered and does not count against that limit.

Text previews require valid UTF-8 without binary control characters. Invalid UTF-8, NUL bytes, other binary controls, directories, symbolic links, special files, and hard-linked aliases are rejected. Filename extensions supply only fixed syntax-language hints and never select an executable response type. Raster images are classified from their bytes rather than their filename and accept only PNG, JPEG, GIF, WebP, and AVIF signatures.

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

The rendered endpoint uses `Content-Type: text/html; charset=utf-8`. The frontend embeds it in an iframe with an empty `sandbox` attribute and also offers an explicit new-tab preview. The response independently applies a CSP sandbox in both contexts with `default-src 'none'`, allows only inline styles and embedded `data:` images, and blocks base-URL changes, form submissions, ancestor origins other than self, and navigation. No iframe sandbox tokens are granted: scripts, event handlers, application storage, same-origin access, forms, popups, top navigation, and external network requests remain unavailable. The rendered view shows layout and safe CSS, not an executable web application.

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

`GET /api/v1/shares/{shareId}/preview/image?path=...` authenticates and authorizes the request, opens the file through the same share capability, applies the configured preview byte limit, and validates a bounded header for a supported raster signature and safe known dimensions. The file then streams from that already-validated handle in fixed-size chunks rather than being buffered in Rust memory. The response chooses its media type from the signature, never from an extension or uploaded `Content-Type`, and includes the exact metadata length plus the same no-sniffing, no-referrer, private no-store, permissions, and same-origin resource policies. SVG is intentionally excluded because it is active document content.

## Hostile fixtures

Tests keep representative payloads for scripts, event handlers, `javascript:` links, forms, top navigation, popups, meta refresh, external beacons, and SVG/script combinations. Response tests assert that source stays plain text, rendered HTML receives the complete sandbox policy, and raster media types come only from validated signatures. Browser tests assert the rendered iframe has an empty `sandbox` attribute and that hostile content cannot create storage, dialogs, navigation, or completed external responses.
