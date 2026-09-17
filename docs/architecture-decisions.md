# Architecture decisions

## Rust, Axum, and Tokio

Rust provides explicit error handling, predictable memory behavior, and capability-oriented filesystem libraries for the application’s main security boundary. Axum and Tokio supply maintained HTTP and asynchronous I/O primitives without a second runtime service.

## Preact and Vite

Preact provides the component model needed for uploads, navigation, and previews with a small browser footprint. Vite and TypeScript are build-time dependencies only. Compiled assets are embedded in the Rust executable.

## Immutable TOML configuration

Users, shares, grants, limits, and secret-file references are operator configuration. One versioned TOML file avoids ambiguous precedence. Only the configuration path has a CLI/environment bootstrap override. Changes require restart in v1.

## Filesystem data and SQLite runtime state

Files remain normal files in explicitly mounted roots. SQLite stores server-side sessions, while structured audit events go to standard output with the rest of the application logs. This avoids a database service while keeping runtime state separate from immutable configuration.

## Argon2id

Passwords are one-way hashed with Argon2id v19 and unique salts in PHC format. The application enforces lower and upper parameter bounds and limits concurrent verification to preserve availability.

## Capability-scoped filesystem access

Each trusted configured share is opened once as a capability directory. Request paths remain validated relative paths and never regain ambient filesystem authority. Symlinks and special files are rejected in v1.

## One binary and one container process

The frontend is compiled before Rust and embedded in the executable. Releases provide that binary directly and package the identical bytes in a minimal, non-root OCI image. Production requires no Node process, static server, Redis, or external database.
