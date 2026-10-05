/**
 * A TLS front for the E2E server, as a reverse proxy is in production.
 *
 * Crabinet's session cookie is `__Host-` prefixed and `Secure`. Chromium and
 * Firefox store it over plain HTTP on `localhost`, but Playwright's WebKit on
 * Linux does not, so the WebKit projects reach their server through this
 * proxy over HTTPS with a throwaway self-signed certificate. It forwards each
 * request unchanged, `Host` included (the server's same-origin check compares
 * it with `Origin`), and streams both bodies so uploads, downloads, and event
 * streams behave as they do without it.
 *
 * Usage: node e2e/tls-proxy.ts LISTEN_PORT BACKEND_PORT CERT_FILE KEY_FILE
 * Node built-ins only; test use only.
 */
import { readFileSync } from "node:fs";
import { request } from "node:http";
import { createServer } from "node:https";

const [listenPort, backendPort, certFile, keyFile] = process.argv.slice(2);
if (!listenPort || !backendPort || !certFile || !keyFile) {
  console.error(
    "usage: node e2e/tls-proxy.ts LISTEN_PORT BACKEND_PORT CERT_FILE KEY_FILE",
  );
  process.exit(2);
}

const server = createServer(
  { cert: readFileSync(certFile), key: readFileSync(keyFile) },
  (incoming, outgoing) => {
    const upstream = request(
      {
        host: "127.0.0.1",
        port: Number(backendPort),
        method: incoming.method,
        path: incoming.url,
        headers: incoming.headers,
      },
      (response) => {
        // Raw headers keep repeated fields such as Set-Cookie apart.
        outgoing.writeHead(response.statusCode ?? 502, response.rawHeaders);
        response.pipe(outgoing);
        response.on("error", () => outgoing.destroy());
      },
    );
    upstream.on("error", () => {
      if (outgoing.headersSent) outgoing.destroy();
      else outgoing.writeHead(502).end();
    });
    // A client that goes away takes its upstream request with it.
    outgoing.on("close", () => upstream.destroy());
    incoming.pipe(upstream);
  },
);
server.listen(Number(listenPort), "127.0.0.1");
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => process.exit(0));
}
