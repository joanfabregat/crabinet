# Contributing

Thank you for improving Crabinet. Security-sensitive changes need evidence: a clear invariant, focused tests, and an explanation of failure behavior. Start with the [architecture decisions](docs/architecture-decisions.md), [threat model](docs/threat-model.md), [filesystem security design](docs/filesystem-security.md), and the current API notes under `docs/`.

## Repository layout

- `src/`: Axum application, immutable configuration, authentication/session handling, capability-scoped filesystem code, browse/mutation/preview APIs, and embedded assets.
- `web/`: Preact/TypeScript application and Vitest tests. Its production `dist/` is embedded in the Rust binary.
- `tests/`: Rust CLI/config integration fixtures.
- `docs/`: security rationale, current first-party API behavior, and operator details.
- `.github/workflows/`: CI, weekly security scans, and tag-driven release publication.

## Toolchains and isolation

The supported toolchains are pinned in CI: Rust 1.90 and Node 24. Do not execute project Rust, JavaScript, TypeScript, build scripts, or package lifecycle scripts directly on an untrusted host. Run them in a locked-down container, such as rootless Podman with no host credentials mounted, and split dependency work into two phases: fetch and audit with the network but without running any dependency code, then build and test offline.

`web/.npmrc` sets `ignore-scripts=true`, so installs never run lifecycle scripts implicitly. Fetch and audit the locked dependencies with lifecycle scripts disabled:

```sh
cd web
podman run --rm \
  --userns=keep-id \
  --volume "$PWD:/workspace" \
  --workdir /workspace \
  docker.io/library/node:24-bookworm-slim \
  /bin/sh -c 'npm ci --ignore-scripts && npm audit --audit-level=high'
```

Then run esbuild's reviewed install script, the one lifecycle script the build needs, and the checks offline:

```sh
podman run --rm \
  --network none \
  --userns=keep-id \
  --volume "$PWD:/workspace" \
  --workdir /workspace \
  docker.io/library/node:24-bookworm-slim \
  /bin/sh -c '
    set -eu
    export npm_config_nodedir=/usr/local
    npm rebuild esbuild --ignore-scripts=false
    npm run format:check
    npm run lint
    npm run typecheck
    npm test
    npm run build
  '
```

Rust checks, from the repository root in a Rust 1.90 container with `rustfmt`, `clippy`, and `cargo-audit`. Run `cargo fetch --locked` with the network first, then the rest offline, because build scripts and procedural macros execute at compile time:

```sh
cargo audit
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

CI rebuilds the frontend before compiling Rust. If you build locally, do the same so `rust-embed` sees current assets. Never commit `node_modules`, `target`, generated frontend bundles, session databases, secrets, test credentials, or share fixtures containing private data.

### Development server

`npm run dev` in `web` serves the frontend with hot module replacement. To route it through a TLS reverse proxy against a running debug backend, set `CRABINET_DEV_BACKEND_URL` (the backend's base URL, proxied for `/api` and `/health`) and `CRABINET_DEV_PUBLIC_HOST` (the public hostname; HMR then connects over `wss` on port 443). `CRABINET_DEV_GIT_DIR` points at a `.git` directory to show the revision in the UI, and `CRABINET_VITE_CACHE_DIR` moves Vite's cache. Use the synthetic fixtures under `web/e2e/fixtures` as shares, never private data.

## Change expectations

Keep authorization at the server boundary even when the UI hides an operation. Every share access must derive from the authenticated user's immutable grant, every filesystem operation must remain beneath an opened capability, and every mutation must require both a write grant and authenticated CSRF proof. Preserve non-disclosing errors where missing and unauthorized resources must be indistinguishable.

Add tests at the lowest useful level and an integration test when middleware, routing, configuration, or filesystem behavior is involved. Security fixes should include an adversarial regression test. Frontend changes should cover keyboard use, focus, responsive states, request cancellation/races, session expiry, hostile content, and read-only permissions as applicable. Avoid snapshots that conceal behavioral regressions.

Do not weaken size, concurrency, timeout, path, session, or parser bounds without an explicit rationale and resource test. Do not render untrusted HTML with `innerHTML`, add iframe permissions, trust forwarded identity headers, or follow filesystem links without a dedicated threat-model update and review.

## Dependencies

Prefer the standard library and existing audited dependencies. Before adding a package or action:

1. Verify the exact package/repository and maintainer to avoid typosquatting.
2. Check maintenance activity, adoption, transitive dependencies, advisories, license, and whether the capability can be implemented safely without it.
3. Pin GitHub Actions to a full commit SHA and container images to an immutable digest where the workflow supports it.
4. Update the lockfile without bypassing lifecycle-script controls, run the appropriate audit, and review the dependency diff before execution.
5. Confirm `cargo deny check --all-features`, npm's high-severity audit, Semgrep, and Trivy remain clean.

MIT-compatible distribution is enforced for direct/transitive Rust dependencies by `cargo-deny` and for changed GitHub dependency graphs by dependency review. Document any license notice that must accompany a distributed artifact.

## Configuration and documentation

Configuration is strict and versioned. New fields need safe defaults or an explicit format-version decision, validation at startup, redacted errors, an annotated example, documentation, invalid fixtures, and schema coverage. `config.schema.json` must remain semantically equal to `crabinet print-config-schema`; Rust tests enforce this.

Examples must not contain real secrets or usable credentials. Commands should be copyable and specify whether they are development-only. Update the README and security documents when a change alters deployment assumptions, resource sizing, backup semantics, preview behavior, or a trust boundary.

## Pull requests and release preparation

Keep a pull request focused and explain user-visible behavior, security impact, test evidence, and operational changes. Link the issue with `Fixes #N`. All required CI jobs must pass: frontend, Rust, Clippy, browser E2E, dependency policy/review, workflow lint, Semgrep, and Trivy.

Releases are created from signed semantic-version tags matching `vX.Y.Z`. Before tagging:

1. Confirm `main` CI is green and the version/release notes are accurate.
2. Exercise the example configuration, CLI help, schema generation, login, each grant class, previews, uploads, and a disposable mutation.
3. Review dependency and action updates, the threat model, memory measurements, migration/rollback notes, and supported architectures.
4. Tag the exact green commit. The release workflow rebuilds/tests assets, produces static `amd64`/`arm64` archives, SBOMs, checksums, attestations, scans the exact OCI archives, publishes a multi-architecture GHCR image, and attaches artifacts to the GitHub release.

Never bypass a failed scanner or required check to publish. Fix or explicitly document a reviewed false positive in policy before retrying.
