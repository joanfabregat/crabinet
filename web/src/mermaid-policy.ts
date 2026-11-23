// Shared by the production asset server (mirrored in Rust), development
// server, and renderer. The frame has an opaque origin, no session access,
// and no network except loading the application's bundled scripts.
export const MERMAID_FRAME_CSP =
  "sandbox allow-scripts; default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; font-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'";

export const MAX_MERMAID_CHARACTERS = 32_000;
export const MAX_MERMAID_DIAGRAMS = 16;
export const MAX_MERMAID_HEIGHT = 1000;
