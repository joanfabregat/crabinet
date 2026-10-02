# Configuration

Crabinet has one immutable, versioned TOML configuration. The server reads it once and validates the complete policy before opening a listening socket. Changing the file has no effect until Crabinet is restarted.

## Selecting the file

The default path is `config.toml` in the process working directory. `--config PATH` takes precedence over `CRABINET_CONFIG`; these are the only bootstrap overrides. Individual fields cannot be changed with environment variables, which keeps the effective configuration reviewable as one document.

```console
crabinet --config /etc/crabinet/config.toml
CRABINET_CONFIG=/etc/crabinet/config.toml crabinet
crabinet check-config --config /etc/crabinet/config.toml
```

`crabinet check-config` performs the same parsing, policy, secret-file, and share-root checks as server startup without opening a socket. `crabinet print-config-schema` emits JSON Schema for tooling. Unknown fields and format versions are rejected rather than ignored.

## Schema

The top-level fields are:

- `version`: must be `1`.
- `server`: listen address, SQLite path, session-secret file, upload/preview limits, and authentication/session resource limits.
- `auth`: enable password sign-in, OIDC sign-in, or both; optionally enable passkeys with a public origin. `gravatar_enabled` (default `false`) shows Gravatar images for users who have a configured email but no OIDC picture; when enabled, browsers send a hash of that email address to gravatar.com on every page load.
- `users`: local usernames, optional Argon2id password hashes, optional OIDC email bindings, and optional OIDC subject bindings (`oidc_subject`).
- `shares`: stable IDs, user-facing display names, absolute filesystem roots, optional global read-only policy, and grants.

Paths under `server` may be relative to the directory containing the configuration file. The database's parent directory must already exist. Share roots must be absolute existing directories. A share root cannot be `/`, a symbolic link, overlap another share, or contain the configuration file, database, or session-secret file. Crabinet canonicalizes trusted paths once at startup; request paths are handled separately inside those capabilities.

Sizes use a positive integer and one binary unit: `B`, `KiB`, `MiB`, or `GiB`. The preview limit cannot exceed the upload limit.

`server.max_connections` defaults to 1024 and accepts 1–65535. It caps simultaneously open client connections, counting idle keep-alive connections, open event streams, and in-flight uploads and downloads; a connection accepted above the cap is closed immediately without a response, and the first such close after a period below the cap is logged as a warning. Keep the process's open-file limit comfortably above the cap.

`server.header_read_timeout_seconds` defaults to 300 and accepts 5–3600 seconds. A client must send each complete request head within this time of the server starting to wait for it; otherwise the connection is closed without a response. The timer runs on a new connection and also between requests on an idle keep-alive connection, so it doubles as the idle keep-alive timeout. The default is deliberately longer than common reverse-proxy idle upstream timeouts, such as Caddy's two minutes and nginx's 60 seconds, so a proxy closes its idle upstream connections before Crabinet does and never reuses one that Crabinet has just closed. Operators who expose the port directly can lower it; slow or idle clients are bounded by `server.max_connections` either way. Download responses have no whole-request timeout. Upload and text-save request bodies have the fixed idle and absolute deadlines described in [Mutation and upload API](mutations.md), and event streams end after 60 seconds or once their session is no longer valid.

`server.trash_retention_days` defaults to 30 and accepts 1–3650 days. Expired items are eligible for bounded background cleanup at startup and then hourly; each run spends at most about 30 seconds per share. Trash is shared within each writable share; its content counts toward that share's quota.

Usernames and share IDs are case-sensitive, stable identifiers containing 1–64 ASCII letters, digits, dots, underscores, or hyphens; a share ID must also start with a letter or digit. A share's required `name` is a separate user-facing label of 1–128 characters; changing it does not change URLs or identity. Display names cannot contain control characters or leading/trailing whitespace. Duplicate identifiers, duplicate grants, and grants naming an absent user are rejected. A user absent from a share's grants has no access. Permissions are `read` and `write`; `read_only = true` on a share always reduces write grants to read access. Crabinet creates private mode-`0700` `.crabinet` and `.crabinet/staging` directories at the root of every share with an effective write grant. `.crabinet` and the legacy `.index-staging` name are reserved and hidden from the file API; `staging` remains an ordinary name elsewhere. A writable share refuses startup while `.index-staging` exists. Read-only shares create no staging state.

See [`config.example.toml`](../config.example.toml) for an annotated configuration and run `crabinet print-config-schema` for a machine-readable schema.

## Secrets and password hashes

The session secret is referenced by filename instead of being embedded in TOML. It must be a regular, non-symlink file containing 32–4096 random bytes. On Unix, Crabinet rejects the session secret and the OIDC client secret when their mode grants any permission to group or other users (`mode & 0o077`), both at startup and in `check-config`, with an error naming the fix, such as ``run `chmod 600 session.key` as its owner``. Mode `0600` or `0400` is accepted, so the file must be owned by the user that runs Crabinet. A container secret mount must therefore expose the file to that user with an owner-only mode: on the host, `chmod 600` the file before bind-mounting it, or give a Podman secret explicit `uid`, `gid`, and `mode=0400` options, because its default mode `0444` is world-readable. Keep it outside every shared root. Its value is read once and is redacted from debug output and errors.

The configuration file holds password hashes. When it is accessible by group or other users, Crabinet logs a warning at startup and in `check-config` but still loads it; restrict it with `chmod 600` as well.

Generate password hashes interactively:

```console
crabinet hash-password
```

The command reads the password twice with terminal echo disabled and writes only the resulting salted Argon2id v19 PHC string to standard output. It refuses a password longer than 4096 bytes, because sign-in rejects such a password. It uses `m=65536` KiB, `t=3`, and `p=1`. A clear-text password is deliberately not accepted as a command-line argument or environment variable. Copy the PHC string into the applicable `users` entry. Unsupported algorithms, malformed PHC strings, or hashes without salt and accepted work-factor parameters are rejected during validation.

`auth_max_concurrent` bounds simultaneous Argon2 work. The default is one and is appropriate for a small pod. Generated hashes use 64 MiB; accepted configuration hashes are bounded at 256 MiB, so size the container for the largest accepted configured hash multiplied by this concurrency plus normal process memory. Benchmark the release binary in the intended container before increasing it. `session_idle_timeout_seconds` and `session_absolute_timeout_seconds` default to 30 minutes and 12 hours. `login_attempts_per_minute` (default 5, 1–1000) limits attempts per normalized account identifier and source address each minute. `login_attempts_per_source_per_minute` (default 20, 1–10000) limits attempts from one source address each minute across all usernames, before any Argon2 work, so one source cannot keep the verifier busy by cycling usernames; keep it at least as large as `login_attempts_per_minute`, or the per-account limit never applies. Both use bounded in-memory tracking described in [authentication](authentication.md). `max_sessions_per_user` and `max_sessions_total` default to 16 and 4096; successful login removes the deterministically oldest excess rows after expired-session cleanup.

### Trusted reverse proxies

The source address used by both login limiters is the TCP peer unless `server.trusted_proxies` is set. Behind a reverse proxy every client shares the proxy's address, so list the proxy's own addresses:

```toml
[server]
trusted_proxies = ["127.0.0.1", "::1", "192.0.2.0/28", "2001:db8:1::/64"]
trusted_proxy_header = "x-forwarded-for"
```

- `trusted_proxies` (default empty) takes up to 64 IPv4 or IPv6 addresses or CIDR ranges. A bare address means that single host. Ranges must not have host bits set, IPv4-mapped IPv6 forms must be written as IPv4, and `0.0.0.0/0` and `::/0` are rejected because they would let any client choose its own address. Empty means forwarding headers are ignored.
- `trusted_proxy_header` is `"x-forwarded-for"` (default) or `"forwarded"` for RFC 7239 `Forwarded: for=…`. Configure the proxy to append the connecting address to that header.

Only when the TCP peer is inside a trusted range does Crabinet read the header. Multiple instances are joined in order, and the addresses are walked from right to left: trusted addresses are skipped, and the first untrusted address is the client. Ports, IPv6 brackets, Forwarded quoting, and IPv4-mapped IPv6 are normalized. If the header is missing, not ASCII, longer than 8 KiB, has more than 64 entries, contains a malformed or obfuscated (`unknown`, `_name`) entry before an untrusted one, or names only trusted addresses, the TCP peer is used. Entries a client prepends are therefore never chosen while the proxy appends the real address. The resolved address is grouped like a direct peer (IPv6 by /64) and only selects rate-limit buckets.

Set `disabled = true` on a user to reject both new logins and sessions that remain in SQLite. The committed example is deliberately disabled so copying it cannot activate its illustrative hash. Because configuration is immutable, this takes effect when Crabinet restarts. Re-enabling a user requires a usable method under the selected authentication settings.

## OIDC sign-in

Set `auth.oidc_enabled = true` and provide `[auth.oidc]` with the HTTPS issuer URL, client ID, path to a client-secret file, and the public HTTPS callback URL ending in `/api/v1/auth/oidc/callback`. Register that exact callback with the provider. The provider must support discovery, authorization-code flow, PKCE S256, `client_secret_basic`, and signed RS256 or ES256 ID tokens. Crabinet checks discovery and signing keys before listening; a provider that cannot be reached or does not match the configured issuer prevents startup. `check-config` validates local settings and secret files without contacting the provider.

The provider must return `email` and `email_verified = true` in the signed ID token or at its UserInfo endpoint. Crabinet calls UserInfo only after verifying the ID token and requires its `sub` to match. It matches the email to a unique `users.email` value, ignoring ASCII letter case. An unknown or unverified email receives no local session. Configure only a provider whose verified-email policy you trust: reassignment of a verified address at that provider can transfer the corresponding Crabinet account unless the user is also bound to a subject. Set `oidc_subject` on a user to require the ID token's `sub` claim to equal it as well as the verified email; a token with the right email and another subject receives no session. Leave it unset to match by email alone. See [authentication](authentication.md#binding-an-oidc-subject) for finding the value. Users still receive only their locally configured share grants. The provider's authorization code, access token, and ID token stay on the server.

Password sign-in remains enabled by default. Its form accepts a configured username or email address. With both methods enabled, users can choose either method on the sign-in page. Set `auth.password_enabled = false` to require OIDC for initial enrollment and recovery; anonymous visitors still see the sign-in page. A user without `password_hash` can sign in by OIDC and must have an email binding. Crabinet rejects an enabled user with no usable initial method, an OIDC section that is incomplete, and a configuration that disables both initial methods. To recover from an unavailable provider when passwords are disabled, an operator must restore provider access or enable password sign-in with a valid hash, validate the configuration, and restart Crabinet.

## Passkeys

Set `[auth.passkeys] origin = "https://files.example.com"` to enable passkeys. The origin must exactly match the public HTTPS origin used by browsers, including any nondefault port, and cannot include a path, query, or fragment. Crabinet stores WebAuthn credentials and stable user handles in the same SQLite database as sessions. Users first sign in with OIDC or a password, then add and name passkeys in Settings. They may keep up to 20 keys, rename them, and remove them independently. Sign-in uses discoverable credentials only: the browser offers the passkeys it holds for this site without asking for an account name. Adding a passkey requires a session that signed in within the last 10 minutes. A passkey signs in to the same configured user account and receives the same session and grants. Lost keys can be replaced after OIDC or password sign-in; keep one of these initial methods enabled for enrollment and recovery. Registration challenges expire after five minutes and sign-in challenges after two; both are single use and held in process memory, so an in-progress ceremony must restart if the server restarts or a load balancer routes its two requests to different replicas.

This version migrates the SQLite database to schema version 4 at startup, even if passkeys are not enabled. Take a consistent database backup before upgrading; an older binary rejects the migrated schema, so rollback requires restoring that backup.

An unrecognized identity sees an error page with a Disconnect link. When discovery advertises an OIDC logout endpoint, Disconnect sends the browser there; otherwise the page explains that the user must sign out at the provider separately. The existing Crabinet logout ends only the local session. Behind a reverse proxy, preserve the public `Host` and use HTTPS for the callback and browser traffic. OIDC configuration changes require a restart.

## Deployment checklist

1. Copy the example and replace `/srv/crabinet/documents` with the intended absolute directory.
2. Create the database and secret parent directories outside all shares.
3. Generate at least 32 random bytes into the secret file and make it owner-only (`chmod 600`); do the same for an OIDC client secret and the configuration file.
4. For password sign-in, generate each password hash with `crabinet hash-password`. For OIDC, configure a verified email binding, optionally an `oidc_subject`, and register the exact callback URL with the provider.
5. Run `crabinet check-config --config PATH` as the same OS user that will run the service.
6. Restart the service after every configuration change.
