# Preview security contract

## V1 behavior

Preview input is untrusted. Every HTTP preview handler must extract the authenticated identity, resolve the requested share grant again for that request, and pass only an `AuthorizedShare` plus a validated `VirtualPath` to `preview::load`. The preview module cannot accept an ambient filesystem path. Missing grants and missing entries use the same public `404` response.

The configured preview limit must be greater than zero and no more than the process-wide 16 MiB ceiling. The filesystem implementation compares the opened file's metadata with that limit before allocating, reads at most `limit + 1` bytes to detect a concurrent growth race, and rejects an oversized file instead of returning a partial document. Successful responses therefore always report `truncated: false`.

Text previews require valid UTF-8 without binary control characters. Invalid UTF-8, NUL bytes, other binary controls, directories, symbolic links, special files, and hard-linked aliases are rejected. Filename extensions supply only fixed syntax-language hints and never select an executable response type. Raster images are classified from their bytes rather than their filename and accept only PNG, JPEG, GIF, WebP, and AVIF signatures.

## Text, code, and Markdown

The JSON endpoint returns `{ kind, source, language, size, truncated }`. Source text remains a JSON string and is never interpolated into application HTML. Markdown is returned as `markdown_source`: the server does not render it, resolve embeds, fetch URLs, or interpret raw HTML.

The frontend may render Markdown only after using a reviewed parser configuration that disables raw HTML and a sanitizer that rejects dangerous URL schemes. Rendering must stay in a component that does not use unsanitized `innerHTML`. The backend source-only contract is the security boundary until that frontend work lands.

The v1 frontend uses a smaller safe-readable projection instead of a general Markdown-to-HTML parser: it recognizes a fixed set of block structures and supplies all file content to Preact as text children. It does not create links, images, embeds, or attributes from source, so URL schemes and raw HTML are never activated. A source tab always exposes the exact returned text.

Code highlighting uses Shiki with a fixed language allowlist and dynamically loaded grammars. Highlighted tokens are rendered as Preact text children; generated or uploaded HTML is never assigned through `innerHTML`.

## HTML

The dedicated HTML-source endpoint intentionally uses `Content-Type: text/plain; charset=utf-8`. It returns the exact validated UTF-8 source and does not parse or escape it into an HTML wrapper. Opening this endpoint in an iframe or a new tab therefore remains inert.

The rendered endpoint uses `Content-Type: text/html; charset=utf-8`, but the frontend embeds it only in an iframe with an empty `sandbox` attribute. The response independently applies a CSP sandbox with `default-src 'none'`, allows only inline styles and embedded `data:` images, and blocks base-URL changes, form submissions, ancestor origins other than self, and navigation. No iframe sandbox tokens are granted: scripts, event handlers, application storage, same-origin access, forms, popups, top navigation, and external network requests remain unavailable. The rendered tab shows layout and safe CSS, not an executable web application.

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
