# Development preview

Crabinet has no installed development service on dev-vm. The former `index-dev.service` and `index-dev-backend.service` units, their dedicated `/etc/index-dev` and `/data/services/index-dev` state, and their Podman network were removed. The production service at <https://files.jf.ffwip.com/> is separate.

The routed preview at <https://files-dev.jf.ffwip.com/> runs only while an agent holds the foreground process started by `scripts/dev-preview.sh`. The repo-local launcher uses rootless Podman inside a bounded transient cgroup, a read-only checkout mount, loopback-only port publishing, and the same GCE metadata denial as the task runner. Vite and the debug Rust binary run in one container with synthetic shares and session state in tmpfs. No persistent service, config directory, database, or named Podman network is created.

Before starting, use the constrained Node workflow in [CONTRIBUTING.md](../CONTRIBUTING.md) to install and audit the locked frontend dependencies, and run `~/.claude/local/scripts/run-rust build --locked` to build the debug binary. Then start the preview from the repository root:

```sh
./scripts/dev-preview.sh
```

Keep that command attached while working. Vite updates frontend files through HMR. After changing Rust source, rebuild with the constrained Rust runner; the preview restarts its backend when the debug binary changes. Stop the attached command with Ctrl+C before ending the agent task, and verify the container is gone and the dev URL returns 404. The launcher does not modify `~/bin/run-podman`.
