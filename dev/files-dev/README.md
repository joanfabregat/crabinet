# Routed development preview

This directory is the source of truth for the live Index development environment at <https://files-dev.jf.ffwip.com>. It belongs with the application because it exists only to run this checkout with frontend hot module replacement and automatic Rust rebuilds.

The preview has two processes:

- `index-dev.service` runs Vite against the mounted `web/` checkout. Preact, TypeScript, and CSS changes use Vite HMR over `wss://files-dev.jf.ffwip.com`.
- `index-dev-backend.service` watches `Cargo.toml`, `Cargo.lock`, `src/**/*.rs`, and `tests/**/*.rs`. A successful incremental build replaces the running debug backend; a failed build leaves the last good backend available.

Vite proxies `/api` and `/health` to the backend on the private `index-dev` Podman network. Traefik discovers the frontend container through its labels and routes the development hostname to it. The production service is separate and is not restarted by this environment.

## Isolation

The development environment must use only synthetic shares and its own configuration, session secret, SQLite database, build output, ports, network, and container names. It must never mount production shares, production state, `~/repos` as a share, or `~/scratch`.

Runtime material is intentionally not committed. On the current dev-vm it lives under `/etc/index-dev` and `/data/index-dev`; the checked-in files contain no passwords, password hashes, session keys, cookies, or database state.

Both services use digest-pinned images, read-only root filesystems, dropped capabilities, no-new-privileges, bounded tmpfs mounts, systemd resource ceilings, and link-local metadata denial. The checkout is mounted read-only. Only the isolated Cargo target, reviewed Cargo cache, synthetic shares, and development state are writable.

## Dependency gates

The persistent services never install dependencies. The frontend uses a prebuilt `node_modules` snapshot that is prepared only after a constrained `npm audit --audit-level=high`. It refuses to start if `web/package-lock.json` differs from `package-lock.sha256`. The Rust watcher builds with `--locked` and refuses to start if `Cargo.lock` differs from `Cargo.lock.sha256`.

After changing either lockfile, audit and test through the constrained project runner, review the dependency diff, update the matching SHA-256 file, refresh the dependency snapshot when applicable, and restart the affected service.

## Prepare dependencies

On Joan's dev-vm, prepare and validate the frontend through the constrained Node runner:

```sh
cd ~/repos/index/web
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
  '
```

Audit and test Rust through the constrained runner:

```sh
cd ~/repos/index
~/.claude/local/scripts/run-rust audit
~/.claude/local/scripts/run-rust test --locked --all-targets --all-features
```

Verify the reviewed lock hashes:

```sh
cd ~/repos/index
test "$(sha256sum Cargo.lock | cut -d' ' -f1)" = \
  "$(tr -d '[:space:]' < dev/files-dev/Cargo.lock.sha256)"
test "$(sha256sum web/package-lock.json | cut -d' ' -f1)" = \
  "$(tr -d '[:space:]' < dev/files-dev/package-lock.sha256)"
```

## Runtime material

Create `/etc/index-dev/config.toml` from the repository's `config.example.toml`, using `/var/lib/index/index.sqlite3` for the database, `/run/secrets/index/session.key` for the session secret, and `/shares/repos` plus `/shares/scratch` for the synthetic shares. Generate a new Argon2id verifier with `index hash-password`; never commit the password or verifier. Generate an independent session key of at least 32 random bytes.

The existing dev-vm installation already has this runtime material. Reinstallation should preserve it unless the preview is intentionally reset.

Initialize `/data/index-dev/shares` from `fixtures/` only for a new or explicitly reset environment. Do not recopy fixtures during normal restarts because files created through the development UI are disposable but may still be under active review.

The checked-in systemd units are the application-owned service definitions for the approved current preview. Their installation is an operator action because it changes host state. They mount the watcher scripts and lock hashes directly from this checkout, so this directory remains their source of truth.

## Daily use

Edit files normally in `~/repos/index`:

- changes below `web/` update an open browser through Vite HMR;
- `web/vite.config.ts` changes restart Vite's development server;
- Rust source changes trigger an incremental build and backend restart;
- a lockfile change fails closed until its audit and reviewed hash are updated.

Inspect logs with:

```sh
journalctl -fu index-dev.service
journalctl -fu index-dev-backend.service
```

## Verify

```sh
curl --fail --silent --show-error \
  http://127.0.0.1:18082/health/ready
curl --fail --silent --show-error \
  http://127.0.0.1:18081/health/ready
curl --fail --silent --show-error \
  https://files-dev.jf.ffwip.com/health/ready
curl --fail --silent --show-error \
  https://files-dev.jf.ffwip.com/@vite/client >/dev/null
```

The final request distinguishes the HMR server from the production binary's embedded frontend.
