# Crabinet development preview

For a browser-accessible development preview, use `./scripts/dev-preview.sh` in an attached tool session. Keep the session open only while actively working, then send Ctrl+C and verify that no `crabinet-preview` container remains and <https://files-dev.jf.ffwip.com/health/ready> returns 404.

Before starting, audit and install the locked frontend dependencies through the constrained Node runner and build the debug backend through the constrained Rust runner. The preview uses synthetic fixtures and tmpfs state. Do not install a systemd unit, Quadlet, named Podman network, or persistent `/etc/index-dev` or `/data/services/index-dev` directory for it. Do not modify the shared `~/bin/run-podman` helper for this preview.
