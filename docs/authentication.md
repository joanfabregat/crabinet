# Authentication and sessions

Crabinet authenticates configuration-defined users with Argon2id v19 passwords, verified-email OpenID Connect sign-in, and optionally WebAuthn passkeys, and keeps opaque sessions in SQLite. Clear-text passwords, PHC strings, provider tokens, raw session identifiers, and CSRF tokens are never logged or stored in the database.

## Password verification and memory

`crabinet hash-password` generates `m=65536,t=3,p=1` hashes: one verifier allocates about 64 MiB. Configuration validation accepts a deliberately bounded range (`m=19456..262144`, `t=2..10`, `p=1..16`) and rejects unknown algorithms, malformed hashes, missing salt/output, and parameters outside it. An unknown or disabled username performs verification against a fixed Argon2id hash before returning the same `401` body used for an incorrect password.

`server.auth_max_concurrent` is a semaphore limit, not a throughput target. Keep the default of one in memory-constrained pods. The upper memory bound attributable to password verification is approximately `auth_max_concurrent × largest configured m`, plus allocator and process overhead. Benchmark the statically linked release artifact under the pod's actual memory limit before increasing the value.

The reproducible release-profile smoke benchmark is:

```console
cargo test --release benchmark_default_argon2_verification_profile -- --ignored --nocapture
```

On the constrained dev-vm runner on 2026-09-16, three default-profile verifications completed in 413.6 ms (137.9 ms mean). This is a reference measurement, not a capacity promise. For the initial low-memory deployment, the documented maximum safe verifier count is **one**. For a different pod, reserve normal process memory and safety headroom first, then cap concurrency at no more than `floor(remaining bytes / largest configured Argon2 m bytes)` and validate under the real cgroup limit.

The login limiter keys attempts by a fixed-size SHA-256 digest of the trimmed, ASCII-lowercased account identifier plus the transport peer IP. It never retains an attacker-sized identifier, retains at most 4096 recent keys, and never changes the case-sensitive username used for authentication. Password sign-in accepts a configured username or email address. Usernames must satisfy the configured 64-byte ASCII identifier grammar before account lookup. Passwords may contain arbitrary Unicode and are processed without truncation up to 4096 UTF-8 bytes; larger, malformed, or otherwise invalid credentials receive the same generic authentication failure and are never copied into an Argon2 worker or logged.

## Passkey verification

Passkey registration requires an active session and its CSRF token. A registration challenge is bound to that session, used once, and expires after five minutes. WebAuthn validates the configured HTTPS origin and relying party ID, the challenge, the authenticator's proof of possession, and user verification. Each configured user has a stable random WebAuthn user handle and may store up to 20 named discoverable credentials. The name is only a local label; renaming it does not change the authenticator. The sign-in page starts a discoverable ceremony without a username or email; the authenticator presents its stored credentials, and the server maps the selected credential and user handle to an enabled configured user. The API still accepts a username or configured email for older non-discoverable credentials, but the current UI does not offer that flow. Successful verification creates an ordinary Crabinet session. Removing a key deletes its credential record, while the other keys and OIDC or password sign-in remain available. Unrecognized and disabled users receive no passkey session. Passkey start requests use the same rate limiter as password sign-in, with a fixed account bucket for discoverable ceremonies and the transport peer address for both flows; a shared proxy should also enforce a per-client limit.

## Account pictures

When OIDC supplies a valid Google profile picture URL, Crabinet includes it in the session response. Otherwise, if the configured user has an email address, the server returns a Gravatar URL derived from the SHA-256 hash of that email after trimming whitespace and folding ASCII letters to lowercase. The browser then requests the image from Gravatar, which receives the hash and the browser's network address. If no email is configured, no account picture is shown. This external image request is currently not configurable.

## Session design

- Session identifiers contain 256 random bits from the operating system CSPRNG and are sent only in a `Secure; HttpOnly; SameSite=Strict; Path=/` cookie.
- SQLite stores only `HMAC-SHA-256(session secret, domain || session identifier)`, the username, and timestamps. Possession of the database alone does not reveal usable cookies.
- A successful login atomically deletes any presented old session before inserting the new session. Logout deletes the session and expires the cookie. Replays then fail.
- Idle and absolute expirations are enforced server-side. Expired records are deleted on access and old rows are boundedly cleaned during login.
- Successful login enforces configured per-user and global session caps (16 and 4096 by default) by deleting deterministic oldest rows. Persistent state therefore stays bounded even if a client suppresses its previous cookie.
- Every authenticated request checks the user against the immutable in-memory configuration. Removed or disabled users therefore lose access after restart even if SQLite still contains a row.
- The CSRF token is a domain-separated keyed digest of the raw session identifier. It is bound to that session, returned by the session APIs, and never placed in browser storage by the frontend.

On Unix, Crabinet creates a missing SQLite database as mode `0600`. It does not change permissions on a pre-existing operator-managed database; deployments should provision that file with an appropriately restrictive owner and mode.

## State-changing requests

Login and logout require an `Origin` or `Referer` whose HTTP(S) authority exactly matches `Host`. If `Sec-Fetch-Site` is present it must be `same-origin`. Authenticated mutations additionally require `X-CSRF-Token` and should use `auth::require_state_change`; read-only protected route groups should use `auth::require_authentication`.

Reverse proxies must preserve the original `Host`. The application deliberately does not trust forwarded client-address headers; login throttling uses the TCP peer address. If a reverse proxy is shared by many users, apply an additional rate limit at that proxy.
