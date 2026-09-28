# Authentication and sessions

Crabinet authenticates configuration-defined users with Argon2id v19 passwords, verified-email OpenID Connect sign-in, and optionally WebAuthn passkeys, and keeps opaque sessions in SQLite. Clear-text passwords, PHC strings, provider tokens, raw session identifiers, and CSRF tokens are never logged or stored in the database.

## Password verification and memory

`crabinet hash-password` generates `m=65536,t=3,p=1` hashes: one verifier allocates about 64 MiB. Configuration validation accepts a deliberately bounded range (`m=19456..262144`, `t=2..10`, `p=1..16`) and rejects unknown algorithms, malformed hashes, missing salt/output, and parameters outside it. An unknown or disabled username performs verification against a dummy Argon2id hash before returning the same `401` body used for an incorrect password. The dummy hash uses the most expensive parameters among the configured hashes, so response time does not reveal which accounts exist when an operator uses non-default parameters.

`server.auth_max_concurrent` is a semaphore limit, not a throughput target. Keep the default of one in memory-constrained pods. The upper memory bound attributable to password verification is approximately `auth_max_concurrent × largest configured m`, plus allocator and process overhead. Benchmark the statically linked release artifact under the pod's actual memory limit before increasing the value. A login takes its verifier slot before consulting the limiter and hands the slot to the Argon2 worker, so a client that disconnects mid-verification cannot free the slot while the computation still runs. A request that waits more than 10 seconds for a slot receives `429` with code `busy`.

The reproducible release-profile smoke benchmark is:

```console
cargo test --release benchmark_default_argon2_verification_profile -- --ignored --nocapture
```

In a constrained rootless container on 2026-09-16, three default-profile verifications completed in 413.6 ms (137.9 ms mean). This is a reference measurement, not a capacity promise. For the initial low-memory deployment, the documented maximum safe verifier count is **one**. For a different pod, reserve normal process memory and safety headroom first, then cap concurrency at no more than `floor(remaining bytes / largest configured Argon2 m bytes)` and validate under the real cgroup limit.

The login limiter keys attempts by a fixed-size SHA-256 digest of the trimmed, ASCII-lowercased account identifier plus the transport peer address, with IPv6 peers grouped by /64 and IPv4-mapped addresses treated as IPv4. It never retains an attacker-sized identifier and retains at most 4096 recent keys. When the map is full, the oldest key that has not exhausted its window is dropped; an exhausted window is never evicted, and new keys are refused while every tracked key is exhausted. Passwords longer than 4096 bytes are rejected before they reach the limiter. The limiter never changes the case-sensitive username used for authentication. Password sign-in accepts a configured username or email address. Usernames must satisfy the configured 64-byte ASCII identifier grammar before account lookup. Passwords may contain arbitrary Unicode and are processed without truncation up to 4096 UTF-8 bytes; larger, malformed, or otherwise invalid credentials receive the same generic authentication failure and are never copied into an Argon2 worker or logged.

## Passkey verification

Passkey registration requires an active session that signed in within the last 10 minutes, plus its CSRF token; an older session receives `403` with code `reauthentication_required`, so a stolen long-lived cookie cannot enroll a persistent credential. A registration challenge is bound to that session, used once, and expires after five minutes; each user holds at most four pending registrations. WebAuthn validates the configured HTTPS origin and relying party ID, the challenge, the authenticator's proof of possession, and user verification. Each configured user has a stable random WebAuthn user handle and may store up to 20 named credentials, all registered as discoverable. The name is only a local label; renaming it does not change the authenticator. Successful registration is written to the audit log. Sign-in always uses a discoverable ceremony: a supplied username is ignored, so the response never reveals whether an account exists or exposes its credential IDs. Sign-in challenges are single use, expire after two minutes, and are held in a bounded process-wide map of 4096 entries that drops the oldest ceremony instead of refusing new ones. Successful verification creates an ordinary Crabinet session. Removing a key deletes its credential record, while the other keys and OIDC or password sign-in remain available. Unrecognized and disabled users receive no passkey session. At startup Crabinet deletes sessions, per-user preferences, and passkeys that belong to usernames no longer present in the configuration, so a new user given a removed name inherits none of them.

## Account pictures

When OIDC supplies a valid Google profile picture URL, Crabinet includes it in the session response; the frontend displays only `https` URLs on `lh3.googleusercontent.com` or `www.gravatar.com`. Otherwise, when `auth.gravatar_enabled = true` and the configured user has an email address, the server returns a Gravatar URL derived from the SHA-256 hash of that email after trimming whitespace and folding ASCII letters to lowercase. The browser then requests the image from Gravatar, which receives the hash and the browser's network address. Gravatar is off by default; with it off, or with no email configured, no account picture is shown.

## Session design

- Session identifiers contain 256 random bits from the operating system CSPRNG and are sent only in the `__Host-crabinet_session` cookie with `Secure; HttpOnly; SameSite=Strict; Path=/` and no `Domain`. The `__Host-` prefix stops a sibling subdomain from planting or shadowing it.
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

## OpenID Connect transactions

The OIDC start endpoint keeps no per-attempt server state. It sets a `__Host-crabinet_oidc_state` cookie (`Secure; HttpOnly; SameSite=Lax; Path=/`, five minutes) carrying the `state`, its expiry, and the key of any session being replaced, authenticated with an HMAC key derived from the session secret. The nonce and PKCE verifier are derived from the state with the same key. The callback accepts the transaction only when the cookie, its HMAC, the expiry, and the returned `state` all match, and records the state in a bounded replay set until it expires. Unauthenticated start requests therefore cannot exhaust server memory or block other users' sign-ins.
