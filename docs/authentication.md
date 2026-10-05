# Authentication and sessions

Crabinet authenticates configuration-defined users with Argon2id v19 passwords, verified-email OpenID Connect sign-in, and optionally WebAuthn passkeys, and keeps opaque sessions in SQLite. Clear-text passwords, PHC strings, provider tokens, raw session identifiers, and CSRF tokens are never logged or stored in the database.

## Password verification and memory

`crabinet hash-password` generates `m=65536,t=3,p=1` hashes: one verifier allocates about 64 MiB. It refuses passwords longer than 4096 bytes, which sign-in would reject. Configuration validation accepts a deliberately bounded range (`m=19456..262144`, `t=2..10`, `p=1..16`) and rejects unknown algorithms, malformed hashes, missing salt/output, and parameters outside it. An unknown or disabled username performs verification against a dummy Argon2id hash before returning the same `401` body used for an incorrect password. The dummy hash uses the most expensive parameters among the configured hashes, so response time does not reveal which accounts exist when an operator uses non-default parameters.

`server.auth_max_concurrent` is a semaphore limit, not a throughput target. Keep the default of one in memory-constrained pods. The upper memory bound attributable to password verification is approximately `auth_max_concurrent × largest configured m`, plus allocator and process overhead. Benchmark the statically linked release artifact under the pod's actual memory limit before increasing the value. A login first passes the per-source limiter, which does no Argon2 work, then takes its verifier slot before consulting the per-account limiter, and hands the slot to the Argon2 worker, so a client that disconnects mid-verification cannot free the slot while the computation still runs. A request that waits more than 10 seconds for a slot receives `429` with code `busy`.

The reproducible release-profile smoke benchmark is:

```console
cargo test --release benchmark_default_argon2_verification_profile -- --ignored --nocapture
```

In a constrained rootless container on 2026-09-16, three default-profile verifications completed in 413.6 ms (137.9 ms mean). This is a reference measurement, not a capacity promise. For the initial low-memory deployment, the documented maximum safe verifier count is **one**. For a different pod, reserve normal process memory and safety headroom first, then cap concurrency at no more than `floor(remaining bytes / largest configured Argon2 m bytes)` and validate under the real cgroup limit.

Password sign-in passes two limiters, both keyed on the client's source address: the TCP peer, or with `server.trusted_proxies` the address a trusted proxy reports (see [the configuration guide](configuration.md#trusted-reverse-proxies)). IPv6 sources are grouped by /64 and IPv4-mapped addresses are treated as IPv4.

1. The per-source limiter allows `server.login_attempts_per_source_per_minute` attempts (default 20) from one source each minute, whatever usernames they name. Passkey sign-in starts draw on the same budget (see below), so password attempts and passkey ceremonies from one source together share one allowance. It runs before the request waits for a verifier slot and does no Argon2 work, so a single source cycling random usernames is refused with `429` code `rate_limited` instead of occupying the verifier ahead of other users. Successful sign-ins count too and do not reset it.
2. The per-account limiter allows `server.login_attempts_per_minute` attempts (default 5) per account identifier and source. It keys attempts by a fixed-size SHA-256 digest of the trimmed, ASCII-lowercased account identifier plus the source, and is consulted only after the verifier slot is taken, so new keys are created no faster than verification runs. A successful sign-in clears that account's key for the source.

Each limiter uses a fixed one-minute window, never retains an attacker-sized identifier, and retains at most 4096 recent keys. When a map is full, the oldest key that has not exhausted its window is dropped; an exhausted window is never evicted, and new keys are refused while every tracked key is exhausted. Passwords longer than 4096 bytes are rejected before they reach either limiter. The limiter never changes the case-sensitive username used for authentication. Password sign-in accepts a configured username or email address. Usernames must satisfy the configured 64-byte ASCII identifier grammar before account lookup. Passwords may contain arbitrary Unicode and are processed without truncation up to 4096 UTF-8 bytes; larger, malformed, or otherwise invalid credentials receive the same generic authentication failure and are never copied into an Argon2 worker or logged.

## Passkey verification

Passkey registration requires an active session that signed in within the last 10 minutes, plus its CSRF token; an older session receives `403` with code `reauthentication_required`, so a stolen long-lived cookie cannot enroll a persistent credential. A registration challenge is bound to that session, used once, and expires after five minutes; each user holds at most four pending registrations. WebAuthn validates the configured HTTPS origin and relying party ID, the challenge, the authenticator's proof of possession, and user verification. Each configured user has a stable random WebAuthn user handle and may store up to 20 named credentials, all registered as discoverable. The name is only a local label; renaming it does not change the authenticator. Successful registration is written to the audit log. Sign-in always uses a discoverable ceremony: a supplied username is ignored, so the response never reveals whether an account exists or exposes its credential IDs. Sign-in challenges are single use, expire after two minutes, and are held in a bounded process-wide map of 4096 entries that drops the oldest ceremony instead of refusing new ones. Before a ceremony is stored, its start counts against the per-source sign-in budget shared with password sign-in, using the same trusted-proxy source resolution; a source over budget receives `429` with code `rate_limited` and stores nothing, so one source cannot flood the map and evict other users' in-progress ceremonies. Successful verification creates an ordinary Crabinet session. Removing a key deletes its credential record, while the other keys and OIDC or password sign-in remain available. Unrecognized and disabled users receive no passkey session. At startup Crabinet deletes sessions, per-user preferences, and passkeys that belong to usernames no longer present in the configuration, so a new user given a removed name inherits none of them.

## Account pictures

When OIDC supplies a valid Google profile picture URL, Crabinet includes it in the session response; the frontend displays only `https` URLs on `lh3.googleusercontent.com` or `www.gravatar.com`. Otherwise, when `auth.gravatar_enabled = true` and the configured user has an email address, the server returns a Gravatar URL derived from the SHA-256 hash of that email after trimming whitespace and folding ASCII letters to lowercase. The browser then requests the image from Gravatar, which receives the hash and the browser's network address. Gravatar is off by default; with it off, or with no email configured, no account picture is shown.

## Session design

- Session identifiers contain 256 random bits from the operating system CSPRNG and are sent only in the `__Host-crabinet_session` cookie with `Secure; HttpOnly; SameSite=Strict; Path=/` and no `Domain`. The `__Host-` prefix stops a sibling subdomain from planting or shadowing it.
- SQLite stores only `HMAC-SHA-256(session secret, domain || session identifier)`, the username, and timestamps. Possession of the database alone does not reveal usable cookies.
- A successful login atomically deletes any presented old session before inserting the new session. Logout deletes the session and expires the cookie. Replays then fail. An open directory event stream re-checks its session every 15 seconds without extending it and ends once the session is gone or expired.
- Session reads and sign-in validate the saved start folder with a directory lookup on the blocking thread pool, so a slow share filesystem cannot stall the async workers that serve authentication. Session lookups do not count against the request-path blocking-work limit, so sign-in and sign-out stay available while it is saturated.
- Idle and absolute expirations are enforced server-side. Expired records are deleted on access and old rows are boundedly cleaned during login.
- Successful login enforces configured per-user and global session caps (16 and 4096 by default) by deleting deterministic oldest rows. Persistent state therefore stays bounded even if a client suppresses its previous cookie.
- Every authenticated request checks the user against the immutable in-memory configuration. Removed or disabled users therefore lose access after restart even if SQLite still contains a row.
- The CSRF token is a domain-separated keyed digest of the raw session identifier. It is bound to that session, returned by the session APIs, and never placed in browser storage by the frontend.

On Unix, Crabinet creates a missing SQLite database as mode `0600`. It does not change permissions on a pre-existing operator-managed database; deployments should provision that file with an appropriately restrictive owner and mode.

## State-changing requests

Login and logout require an `Origin` or `Referer` whose HTTP(S) authority exactly matches `Host`. If `Sec-Fetch-Site` is present it must be `same-origin`. Authenticated mutations additionally require `X-CSRF-Token` and should use `auth::require_state_change`; read-only protected route groups should use `auth::require_authentication`.

Reverse proxies must preserve the original `Host`. By default the application does not trust forwarded client-address headers and login throttling uses the TCP peer address; behind a proxy every client then shares one source, so one client's failures can lock an account out of password sign-in for all of them. Setting `server.trusted_proxies` makes Crabinet read `X-Forwarded-For` or `Forwarded` from those peers only, walking the header right to left past trusted hops, and fall back to the TCP peer when the header is missing or malformed. The resolved address only selects rate-limit buckets; it never grants access.

## OpenID Connect transactions

The OIDC start endpoint keeps no per-attempt server state. It sets a `__Host-crabinet_oidc_state` cookie (`Secure; HttpOnly; SameSite=Lax; Path=/`, five minutes) carrying the `state`, its expiry, the key of any session being replaced, and the in-app location to return to, authenticated with an HMAC key derived from the session secret. The nonce and PKCE verifier are derived from the state with the same key. The callback accepts the transaction only when the cookie, its HMAC, the expiry, and the returned `state` all match, and records the state in a bounded replay set until it expires. Unauthenticated start requests therefore cannot exhaust server memory or block other users' sign-ins.

### Returning to the page after sign-in

The sign-in page passes the location the user opened, or was on when the session expired, as `GET /api/v1/auth/oidc/start?return_to={path and query}`; at the app root it passes none. The server keeps the location only when it is a same-origin app path: it starts with a single `/`, uses only visible ASCII with no backslash or `#`, is at most 2 KiB, and, once percent-decoded, still starts with a single `/`, contains no control characters, backslashes, or `.` or `..` segments, and does not point under `/api` or `/health`. An invalid, repeated, or missing `return_to` is dropped without an error. A kept location travels only in the authenticated transaction cookie, never in the `state` or anything else sent to the provider, and nothing the provider returns can change it. After a successful callback the browser is redirected (`303`) to the location, which the app treats as a direct link; without one it lands on `/`, where the user's start folder applies. Failed callbacks behave as before. Password and passkey sign-in happen within the page, so the location never changes.

### Binding an OIDC subject

By default an OIDC sign-in maps to the user whose `email` equals the provider's verified email. A user may also set `oidc_subject` to the provider's `sub` claim, an opaque, case-sensitive account identifier of at most 255 ASCII characters. The ID token must then carry exactly that subject as well as the verified email; a matching email with another subject is refused like an unknown identity and audited with reason `subject_mismatch`. Users without `oidc_subject` keep the email-only behavior. An `oidc_subject` requires an `email` on the same user.

The subject is the `sub` value in the ID token the provider issues for that account; Crabinet does not log it. Google's `sub` is a stable numeric account ID that does not change when the account's email address changes, and Google documents it as the identifier to key accounts on. Obtain it from the provider's administration tools or from an ID token issued to the user, then add it to the configuration and restart. Binding the subject means a verified email address that the provider later reassigns to another account can no longer sign in as this user.

## Audit events

Security events are written to the structured log with `audit = true`, an `operation`, an `outcome`, and for refusals a stable `reason`, in the same shape as the mutation events described in [mutations](mutations.md). They are emitted inside the request span, so each JSON line also carries the server-generated `request_id`. Sign-in events include `client_address`, the resolved address the login limiters use (see [the configuration guide](configuration.md#trusted-reverse-proxies)).

| Operation | Outcome | Subject and reasons |
| --- | --- | --- |
| `password_login` | `success` or `rejected` | `subject` for a configured account. Reasons: `bad_credentials`, `disabled`, `method_unavailable` (password sign-in disabled or no hash), `rate_limited_account`, `rate_limited_source`, `busy`, `malformed_request`, `cross_origin`, `internal_error`. An attempted name that matches no account is logged only as `identifier`, a keyed HMAC digest of its trimmed, lowercased form under the session secret, so repeated attempts correlate without recording what was typed. |
| `oidc_login` | `success` or `rejected` | Reasons: `invalid_transaction`, `provider_error`, `missing_code`, `token_exchange_failed`, `invalid_id_token`, `userinfo_failed`, `userinfo_subject_mismatch`, `unverified_email`, `unknown_identity` (with the email's keyed `identifier`), `disabled`, `subject_mismatch`, `internal_error`. |
| `passkey_login` | `success` or `rejected` | Reasons: `malformed_request`, `cross_origin`, `method_unavailable`, `invalid_challenge`, `invalid_credential`, `unknown_credential`, `disabled`, `internal_error`. |
| `passkey_register` | `success` | The registering `subject` and the new passkey ID. |
| `logout` | `success` | The signed-out `subject` and `client_address`. |
| `session` | `ended` | A stored session refused on use: `expired` (idle or absolute timeout) or `revoked` (user removed or disabled). |
| Read route, for example `directory`, `download`, or `preview` | `rejected` | `no_grant`: the `subject` named a `share_id` it holds no grant for. The client still receives the ordinary non-disclosing `404`; a syntactically invalid share ID is not logged. |

Passwords, password hashes, cookies, session identifiers, CSRF tokens, OIDC authorization codes and tokens, provider subjects, and file contents never appear in these events.
