# Routed development preview

The development preview is served at <https://files-dev.jf.ffwip.com/>. It is separate from the released image at `files.jf.ffwip.com`. Two host-managed rootless Podman services run it: `index-dev-backend.service` watches and rebuilds the Rust backend, while `index-dev.service` runs Vite with hot module replacement for the frontend. The installed unit names and `/data/services/index-dev` paths predate the Crabinet rename.

The frontend mounts this checkout's `web/` directory read-only and uses audited dependencies from `/data/services/index-dev/build/node_modules`. The backend mounts the checkout read-only and writes build outputs under `/data/services/index-dev/build/target`. Vite proxies `/api` and `/health` to the backend over their private Podman network. The only published ports are loopback `18081` for Vite and `18082` for the backend; Traefik exposes the HTTPS route.

The installed frontend unit passes `CRABINET_DEV_BACKEND_URL`, `CRABINET_DEV_PUBLIC_HOST`, `CRABINET_DEV_GIT_DIR`, and `CRABINET_VITE_CACHE_DIR`. Vite also accepts the former `INDEX_` names for compatibility with older local units. The installed host service paths and unit names still predate the Crabinet rename.

## Restart and verify

Both services check the current dependency lockfile against a recorded SHA-256 hash before executing dependencies. When a lockfile changes, audit it through the `run-rust` or `run-node` constrained runner, review the diff, then update the corresponding hash under `/data/services/index-dev/host/`. Refresh `/data/services/index-dev/build/node_modules` when the frontend dependency set changes. A package-name-only change does not require a dependency reinstall.

```sh
sudo systemctl daemon-reload
sudo systemctl restart index-dev-backend.service
sudo systemctl restart index-dev.service

curl --fail --silent --show-error \
  http://127.0.0.1:18082/health/ready
curl --fail --silent --show-error \
  http://127.0.0.1:18081/health/ready
curl --fail --silent --show-error \
  https://files-dev.jf.ffwip.com/health/ready
```

The backend launcher is `/data/services/index-dev/host/backend-watch.sh`, and the frontend launcher is `/data/services/index-dev/host/frontend-start.sh`. Check `systemctl status` and `journalctl -u` for either unit when a restart fails. The host units still mount `/home/joan/repos/index`; after renaming the checkout directory, update both units' mount paths and restart them. Do not restart `index.service` for a development preview change: it runs the separately pinned release image.
