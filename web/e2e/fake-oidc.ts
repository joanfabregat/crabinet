/**
 * A fake OpenID Connect provider for the OIDC end-to-end tests.
 *
 * It implements only what Crabinet uses (discovery, a JWKS, the
 * authorization-code flow with PKCE S256, `client_secret_basic` at the token
 * endpoint, and an RS256 ID token) and refuses anything else, so a change in
 * what Crabinet sends fails the tests instead of passing unnoticed. It serves
 * HTTPS with a certificate from a per-run test CA that Crabinet trusts only
 * through `auth.oidc.ca_file`. The consent page lets a test choose a fixed
 * identity or cancel; nothing is persisted.
 *
 * Usage: node e2e/fake-oidc.ts PORT CERT_FILE KEY_FILE CLIENT_ID
 *          CLIENT_SECRET_FILE REDIRECT_URI READY_FILE
 * Node built-ins only; test use only.
 */
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
  timingSafeEqual,
} from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:https";

const [
  port,
  certFile,
  keyFile,
  clientId,
  clientSecretFile,
  redirectUri,
  readyFile,
] = process.argv.slice(2);
if (
  !port ||
  !certFile ||
  !keyFile ||
  !clientId ||
  !clientSecretFile ||
  !redirectUri ||
  !readyFile
) {
  console.error(
    "usage: node e2e/fake-oidc.ts PORT CERT_FILE KEY_FILE CLIENT_ID CLIENT_SECRET_FILE REDIRECT_URI READY_FILE",
  );
  process.exit(2);
}
const clientSecret = readFileSync(clientSecretFile, "utf8");
const issuer = `https://127.0.0.1:${port}`;

/** The identities the consent page offers; e2e users are in config.toml.in. */
const identities = {
  reader: { sub: "e2e-reader-subject", email: "reader@example.com" },
  writer: { sub: "e2e-writer-subject", email: "writer@example.com" },
  stranger: { sub: "e2e-stranger-subject", email: "stranger@example.com" },
} as const;
type IdentityName = keyof typeof identities;
const isIdentity = (value: string): value is IdentityName =>
  Object.hasOwn(identities, value);

const signingKey = generateKeyPairSync("rsa", { modulusLength: 2048 });
const keyId = randomBytes(8).toString("hex");
const jwks = {
  keys: [
    {
      ...signingKey.publicKey.export({ format: "jwk" }),
      kid: keyId,
      alg: "RS256",
      use: "sig",
    },
  ],
};

interface AuthorizationRequest {
  state: string;
  nonce: string;
  codeChallenge: string;
}
interface Grant extends AuthorizationRequest {
  identity: IdentityName;
  expiresAt: number;
}
/** Consent pages waiting for a decision, and issued codes; both single use. */
const pending = new Map<string, AuthorizationRequest>();
const grants = new Map<string, Grant>();
const CODE_SECONDS = 60;
const MAX_BODY_BYTES = 16 * 1024;

const randomToken = () => randomBytes(32).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);
const sha256 = (value: string) =>
  createHash("sha256").update(value).digest("base64url");
const sameSecret = (left: string, right: string) => {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
};

/** URL-safe tokens of a sane length, as Crabinet's state and nonce are. */
const TOKEN = /^[A-Za-z0-9_-]{20,512}$/;
/** RFC 7636: a challenge is the 43-character base64url SHA-256 digest. */
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
/** RFC 7636: a verifier is 43 to 128 unreserved characters. */
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;

function signIdToken(claims: Record<string, unknown>): string {
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const input = `${encode({ alg: "RS256", typ: "JWT", kid: keyId })}.${encode(claims)}`;
  const signature = sign("sha256", Buffer.from(input), signingKey.privateKey);
  return `${input}.${signature.toString("base64url")}`;
}

/**
 * Parameters that each appear exactly once and are all in `allowed`, or a
 * reason to refuse them.
 */
function singleParameters(
  params: URLSearchParams,
  allowed: readonly string[],
): Map<string, string> | string {
  const values = new Map<string, string>();
  for (const [name, value] of params) {
    if (!allowed.includes(name)) return `unexpected parameter ${name}`;
    if (values.has(name)) return `repeated parameter ${name}`;
    values.set(name, value);
  }
  return values;
}

function refuse(response: ServerResponse, status: number, reason: string) {
  // The reason can quote request parameters; drop line breaks so one cannot
  // forge another log line.
  const logged = reason.replace(/[\r\n]+/g, " ");
  console.error(`fake-oidc: refused (${String(status)}): ${logged}`);
  response.writeHead(status, {
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(`Refused by the fake identity provider: ${reason}\n`);
}

function json(
  response: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
) {
  response.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    ...headers,
  });
  response.end(JSON.stringify(body));
}

function redirect(response: ServerResponse, params: Record<string, string>) {
  const target = new URL(redirectUri!);
  for (const [name, value] of Object.entries(params)) {
    target.searchParams.set(name, value);
  }
  response.writeHead(303, {
    Location: target.toString(),
    "Cache-Control": "no-store",
  });
  response.end();
}

async function readBody(request: IncomingMessage): Promise<string | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) return null;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function discovery(response: ServerResponse) {
  json(response, 200, {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["openid", "profile", "email"],
    claims_supported: ["sub", "email", "email_verified"],
  });
}

/** Validates the authorization request, then shows the consent page. */
function authorize(url: URL, response: ServerResponse) {
  const params = singleParameters(url.searchParams, [
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
  ]);
  if (typeof params === "string") return refuse(response, 400, params);
  const scopes = (params.get("scope") ?? "").split(" ");
  const problem =
    params.get("response_type") !== "code"
      ? "response_type must be code"
      : params.get("client_id") !== clientId
        ? "unknown client_id"
        : params.get("redirect_uri") !== redirectUri
          ? "redirect_uri is not the registered one"
          : !scopes.includes("openid") || !scopes.includes("email")
            ? "scope must include openid and email"
            : !TOKEN.test(params.get("state") ?? "")
              ? "missing or malformed state"
              : !TOKEN.test(params.get("nonce") ?? "")
                ? "missing or malformed nonce"
                : params.get("code_challenge_method") !== "S256"
                  ? "code_challenge_method must be S256"
                  : !CHALLENGE.test(params.get("code_challenge") ?? "")
                    ? "missing or malformed code_challenge"
                    : null;
  if (problem) return refuse(response, 400, problem);
  const id = randomToken();
  pending.set(id, {
    state: params.get("state")!,
    nonce: params.get("nonce")!,
    codeChallenge: params.get("code_challenge")!,
  });
  const choices = Object.entries(identities)
    .map(
      ([name, identity]) =>
        `<button name="identity" value="${name}">Continue as ${identity.email}</button>`,
    )
    .join("\n");
  response.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    // Chromium and WebKit apply form-action to the redirect that follows
    // the form post, so the client's origin must be allowed as well.
    "Content-Security-Policy": `default-src 'none'; form-action 'self' ${new URL(redirectUri!).origin}`,
  });
  response.end(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>Fake identity provider</title>
<h1>Fake identity provider</h1>
<p>Choose the account to sign in to Crabinet with.</p>
<form method="post" action="/authorize/decision">
<input type="hidden" name="request" value="${id}">
${choices}
<button name="identity" value="cancel">Cancel</button>
</form>
</html>
`);
}

/** Redirects back to Crabinet with a code, or with an error on Cancel. */
async function decide(request: IncomingMessage, response: ServerResponse) {
  const body = await readBody(request);
  if (body === null) return refuse(response, 413, "request body too large");
  const params = singleParameters(new URLSearchParams(body), [
    "request",
    "identity",
  ]);
  if (typeof params === "string") return refuse(response, 400, params);
  const id = params.get("request") ?? "";
  const authorization = pending.get(id);
  pending.delete(id);
  if (!authorization) return refuse(response, 400, "unknown consent request");
  const identity = params.get("identity") ?? "";
  if (identity === "cancel") {
    return redirect(response, {
      error: "access_denied",
      state: authorization.state,
    });
  }
  if (!isIdentity(identity)) return refuse(response, 400, "unknown identity");
  const code = randomToken();
  grants.set(code, {
    ...authorization,
    identity,
    expiresAt: now() + CODE_SECONDS,
  });
  redirect(response, { code, state: authorization.state });
}

/** Exchanges a code, checking client authentication and the PKCE verifier. */
async function token(request: IncomingMessage, response: ServerResponse) {
  const invalid = (error: string, reason: string, status = 400) => {
    console.error(`fake-oidc: token refused: ${reason}`);
    json(response, status, { error });
  };
  if (
    request.headers["content-type"]?.split(";")[0]?.trim() !==
    "application/x-www-form-urlencoded"
  ) {
    return invalid("invalid_request", "form body required");
  }
  const authorization = request.headers.authorization ?? "";
  const credentials = authorization.startsWith("Basic ")
    ? Buffer.from(authorization.slice(6), "base64").toString("utf8")
    : "";
  const separator = credentials.indexOf(":");
  if (
    separator < 0 ||
    credentials.slice(0, separator) !== clientId ||
    !sameSecret(credentials.slice(separator + 1), clientSecret)
  ) {
    return invalid(
      "invalid_client",
      "client_secret_basic authentication failed",
      401,
    );
  }
  const body = await readBody(request);
  if (body === null) return invalid("invalid_request", "body too large");
  const params = singleParameters(new URLSearchParams(body), [
    "grant_type",
    "code",
    "redirect_uri",
    "code_verifier",
  ]);
  if (typeof params === "string") return invalid("invalid_request", params);
  if (params.get("grant_type") !== "authorization_code") {
    return invalid("unsupported_grant_type", "grant_type");
  }
  const code = params.get("code") ?? "";
  const grant = grants.get(code);
  // A code is spent by its first exchange, successful or not.
  grants.delete(code);
  if (!grant || grant.expiresAt < now()) {
    return invalid("invalid_grant", "unknown, used, or expired code");
  }
  if (params.get("redirect_uri") !== redirectUri) {
    return invalid("invalid_grant", "redirect_uri differs from the request");
  }
  const verifier = params.get("code_verifier") ?? "";
  if (!VERIFIER.test(verifier) || sha256(verifier) !== grant.codeChallenge) {
    return invalid("invalid_grant", "PKCE verifier does not match");
  }
  const identity = identities[grant.identity];
  const issuedAt = now();
  json(response, 200, {
    access_token: randomToken(),
    token_type: "Bearer",
    expires_in: 300,
    scope: "openid profile email",
    id_token: signIdToken({
      iss: issuer,
      sub: identity.sub,
      aud: clientId,
      azp: clientId,
      iat: issuedAt,
      exp: issuedAt + 300,
      nonce: grant.nonce,
      email: identity.email,
      email_verified: true,
    }),
  });
}

const server = createServer(
  { cert: readFileSync(certFile), key: readFileSync(keyFile) },
  (request, response) => {
    const url = new URL(request.url ?? "/", issuer);
    const route = `${request.method ?? ""} ${url.pathname}`;
    const handled = (() => {
      switch (route) {
        case "GET /.well-known/openid-configuration":
          return discovery(response);
        case "GET /jwks":
          return json(response, 200, jwks);
        case "GET /authorize":
          return authorize(url, response);
        case "POST /authorize/decision":
          return decide(request, response);
        case "POST /token":
          return token(request, response);
        default:
          return refuse(response, 404, `no route for ${route}`);
      }
    })();
    void Promise.resolve(handled).catch((error: unknown) => {
      console.error("fake-oidc: request failed", error);
      if (!response.headersSent) response.writeHead(500);
      response.end();
    });
  },
);
server.listen(Number(port), "127.0.0.1", () => writeFileSync(readyFile, ""));
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => process.exit(0));
}
