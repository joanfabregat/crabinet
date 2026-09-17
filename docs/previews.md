# Preview security contract

## V1 behavior

Preview input is untrusted. Every HTTP preview handler must extract the authenticated identity, resolve the requested share grant again for that request, and pass only an `AuthorizedShare` plus a validated `VirtualPath` to `preview::load`. The preview module cannot accept an ambient filesystem path. Missing grants and missing entries use the same public `404` response.

The configured preview limit must be greater than zero and no more than the process-wide 16 MiB ceiling. The filesystem implementation compares the opened file's metadata with that limit before allocating, reads at most `limit + 1` bytes to detect a concurrent growth race, and rejects an oversized file instead of returning a partial document. Successful responses therefore always report `truncated: false`.

Only valid UTF-8 text without binary control characters is eligible. Invalid UTF-8, NUL bytes, other binary controls, directories, symbolic links, special files, and hard-linked aliases are rejected. Filename extensions supply only fixed syntax-language hints and never select an executable response type.

## Text, code, and Markdown

The JSON endpoint returns `{ kind, source, language, size, truncated }`. Source text remains a JSON string and is never interpolated into application HTML. Markdown is returned as `markdown_source`: the server does not render it, resolve embeds, fetch URLs, or interpret raw HTML.

The frontend may render Markdown only after using a reviewed parser configuration that disables raw HTML and a sanitizer that rejects dangerous URL schemes. Rendering must stay in a component that does not use unsanitized `innerHTML`. The backend source-only contract is the security boundary until that frontend work lands.

The v1 frontend uses a smaller safe-readable projection instead of a general Markdown-to-HTML parser: it recognizes a fixed set of block structures and supplies all file content to Preact as text children. It does not create links, images, embeds, or attributes from source, so URL schemes and raw HTML are never activated. A source tab always exposes the exact returned text.

## HTML

The dedicated HTML-source endpoint intentionally uses `Content-Type: text/plain; charset=utf-8`. It returns the exact validated UTF-8 source and does not parse or escape it into an HTML wrapper. Consequently scripts, event handlers, SVG payloads, forms, popups, meta refreshes, navigation, and network beacons are displayed as source and cannot run. This behavior is the same in an iframe and in a new tab.

Every preview response adds:

- `Content-Security-Policy: sandbox; default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'`;
- `X-Content-Type-Options: nosniff`;
- `Referrer-Policy: no-referrer`;
- `Cache-Control: no-store, private`;
- a restrictive `Permissions-Policy`, `Cross-Origin-Resource-Policy: same-origin`, and `X-Frame-Options: SAMEORIGIN`;
- the fixed `Content-Disposition: inline`, without a user-controlled filename.

The frontend must still use an empty iframe `sandbox` attribute. This is intentional defense in depth rather than permission to enable any sandbox token.

Active uploaded HTML rendering and uploaded JavaScript execution are not supported in v1. Adding them requires a separate origin that receives no application cookies, has no access to application storage, and cannot reach authenticated application APIs. A same-origin `allow-scripts` or `allow-same-origin` exception is forbidden.

## Hostile fixtures

Tests keep representative payloads for scripts, event handlers, `javascript:` links, forms, top navigation, popups, meta refresh, external beacons, and SVG/script combinations. The response tests assert that these bytes remain plain text and that the HTTP sandbox and anti-sniffing headers are present. Browser tests should additionally assert the frontend iframe has an empty `sandbox` attribute; active browser exploit tests become relevant only if a future isolated-origin renderer is introduced.
