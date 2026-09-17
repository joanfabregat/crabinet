# Configuration

Index has one immutable, versioned TOML configuration. The server reads it once and validates the complete policy before opening a listening socket. Changing the file has no effect until Index is restarted.

## Selecting the file

The default path is `config.toml` in the process working directory. `--config PATH` takes precedence over `INDEX_CONFIG`; these are the only bootstrap overrides. Individual fields cannot be changed with environment variables, which keeps the effective configuration reviewable as one document.

```console
index --config /etc/index/config.toml
INDEX_CONFIG=/etc/index/config.toml index
index check-config --config /etc/index/config.toml
```

`index check-config` performs the same parsing, policy, secret-file, and share-root checks as server startup without opening a socket. `index print-config-schema` emits JSON Schema for tooling. Unknown fields and format versions are rejected rather than ignored.

## Schema

The top-level fields are:

- `version`: must be `1`.
- `server`: listen address, SQLite path, session-secret file, upload/preview limits, and authentication/session resource limits.
- `users`: local usernames and Argon2id password hashes.
- `shares`: stable IDs, user-facing display names, absolute filesystem roots, optional global read-only policy, and grants.

Paths under `server` may be relative to the directory containing the configuration file. The database's parent directory must already exist. Share roots must be absolute existing directories. A share root cannot be `/`, a symbolic link, overlap another share, or contain the configuration file, database, or session-secret file. Index canonicalizes trusted paths once at startup; request paths are handled separately inside those capabilities.

Sizes use a positive integer and one binary unit: `B`, `KiB`, `MiB`, or `GiB`. The preview limit cannot exceed the upload limit.

Usernames and share IDs are case-sensitive, stable identifiers containing 1–64 ASCII letters, digits, dots, underscores, or hyphens. A share's required `name` is a separate user-facing label of 1–128 characters; changing it does not change URLs or identity. Display names cannot contain control characters or leading/trailing whitespace. Duplicate identifiers, duplicate grants, and grants naming an absent user are rejected. A user absent from a share's grants has no access. Permissions are `read` and `write`; `read_only = true` on a share always reduces write grants to read access. Index creates a private mode-`0700` `.index-staging` directory at the root of every share with an effective write grant. That name is reserved and hidden from the file API; read-only shares create no staging state.

See [`config.example.toml`](../config.example.toml) for an annotated configuration and run `index print-config-schema` for a machine-readable schema.

## Secrets and password hashes

The session secret is referenced by filename instead of being embedded in TOML. It must be a regular, non-symlink file containing 32–4096 random bytes. On Unix, Index rejects a secret writable by group or other users; read-only container secret mounts remain valid even when group or other users can read them. Keep it outside every shared root and use the narrowest readable permissions supported by the deployment. Its value is read once and is redacted from debug output and errors.

Generate password hashes interactively:

```console
index hash-password
```

The command reads the password twice with terminal echo disabled and writes only the resulting salted Argon2id v19 PHC string to standard output. It uses `m=65536` KiB, `t=3`, and `p=1`. A clear-text password is deliberately not accepted as a command-line argument or environment variable. Copy the PHC string into the applicable `users` entry. Unsupported algorithms, malformed PHC strings, or hashes without salt and accepted work-factor parameters are rejected during validation.

`auth_max_concurrent` bounds simultaneous Argon2 work. The default is one and is appropriate for a small pod. Generated hashes use 64 MiB; accepted configuration hashes are bounded at 256 MiB, so size the container for the largest accepted configured hash multiplied by this concurrency plus normal process memory. Benchmark the release binary in the intended container before increasing it. `session_idle_timeout_seconds` and `session_absolute_timeout_seconds` default to 30 minutes and 12 hours. Login attempts default to five per normalized account identifier and source address per minute, with bounded in-memory tracking. `max_sessions_per_user` and `max_sessions_total` default to 16 and 4096; successful login removes the deterministically oldest excess rows after expired-session cleanup.

Set `disabled = true` on a user to reject both new logins and sessions that remain in SQLite. The committed example is deliberately disabled so copying it cannot activate its illustrative hash. Because configuration is immutable, this takes effect when Index restarts. Password hashes remain mandatory for disabled users so a later re-enable cannot silently restore an invalid credential.

## Deployment checklist

1. Copy the example and replace `/srv/index/documents` with the intended absolute directory.
2. Create the database and secret parent directories outside all shares.
3. Generate at least 32 random bytes into the secret file and apply owner-only permissions.
4. Generate each password hash with `index hash-password`.
5. Run `index check-config --config PATH` as the same OS user that will run the service.
6. Restart the service after every configuration change.
