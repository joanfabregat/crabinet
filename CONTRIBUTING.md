# Contributing

Thank you for improving Crabinet. Security-sensitive changes need evidence: a clear invariant, focused tests, and an explanation of failure behavior. Start with the [architecture decisions](docs/architecture-decisions.md), [threat model](docs/threat-model.md), [filesystem security design](docs/filesystem-security.md), and the current API notes under `docs/`.

## Repository layout

- `src/`: Axum application, immutable configuration, authentication/session handling, capability-scoped filesystem code, browse/mutation/preview APIs, and embedded assets.
- `web/`: Preact/TypeScript application and Vitest tests. Its production `dist/` is embedded in the Rust binary.
- `tests/`: Rust CLI/config integration fixtures.
- `docs/`: security rationale, current first-party API behavior, and operator details.
- `.github/workflows/`: CI, weekly security scans, and tag-driven release publication.

## Toolchains and isolation

The supported toolchains are pinned in CI: Rust 1.90 and Node 24. Do not execute project Rust, JavaScript, TypeScript, build scripts, or package lifecycle scripts directly on an untrusted host. Use the repository's approved constrained container runner or an equivalent locked-down rootless Podman environment.

On Joan's dev-vm, use the shared runners described by the `run-rust`, `run-node`, and `run-playwright` skills. A typical frontend check deliberately installs without scripts, audits, then enables reviewed lifecycle scripts:

```sh
cd web
~/bin/run-podman \
  --network \
  --project "$PWD" \
  --cache npm \
  --memory 4g \
  --cpus 2 \
  --timeout 30m \
  docker.io/library/node:24-bookworm-slim \
  /bin/sh -lc '
    set -eu
    npm ci --ignore-scripts
    npm audit --audit-level=high
    npm rebuild
    npm run format:check
    npm run lint
    npm run typecheck
    npm test
    npm run build
  '
```

Rust commands use the constrained wrapper from the repository root:

```sh
~/.claude/local/scripts/run-rust audit
~/.claude/local/scripts/run-rust fmt --all -- --check
~/.claude/local/scripts/run-rust clippy --all-targets --all-features -- -D warnings
~/.claude/local/scripts/run-rust test --all-targets --all-features
```

CI rebuilds the frontend before compiling Rust. If you build locally, do the same so `rust-embed` sees current assets. Never commit `node_modules`, `target`, generated frontend bundles, session databases, secrets, test credentials, or share fixtures containing private data.

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

Keep a pull request focused and explain user-visible behavior, security impact, test evidence, and operational changes. Link the issue with `Fixes #N`. All required CI jobs must pass: frontend, Rust, dependency policy/review, workflow lint, Semgrep, and Trivy.

Releases are created from signed semantic-version tags matching `vX.Y.Z`. Before tagging:

1. Confirm `main` CI is green and the version/release notes are accurate.
2. Exercise the example configuration, CLI help, schema generation, login, each grant class, previews, uploads, and a disposable mutation.
3. Review dependency and action updates, the threat model, memory measurements, migration/rollback notes, and supported architectures.
4. Tag the exact green commit. The release workflow rebuilds/tests assets, produces static `amd64`/`arm64` archives, SBOMs, checksums, attestations, scans the exact OCI archives, publishes a multi-architecture GHCR image, and attaches artifacts to the GitHub release.

Never bypass a failed scanner or required check to publish. Fix or explicitly document a reviewed false positive in policy before retrying.
