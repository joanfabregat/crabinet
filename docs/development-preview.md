# Development preview

Crabinet has no installed development service on dev-vm. The former `index-dev.service` and `index-dev-backend.service` units, their dedicated `/etc/index-dev` and `/data/services/index-dev` state, and their Podman network were removed. The production service at <https://files.jf.ffwip.com/> is separate.

A future routed preview at <https://files-dev.jf.ffwip.com/> must run in an attached, task-scoped Podman process that the agent stops before ending its work. It must use synthetic shares and temporary session state, keep the checkout read-only, and preserve the runner's metadata and resource controls. Do not recreate persistent units or service directories for it.

The current `~/bin/run-podman` runner does not publish ports or add routes, so the HTTPS development preview is unavailable until a reviewed attached serving mode is added. Use the constrained Rust and Node runners for builds and tests, and the constrained Playwright runner for browser tests in the meantime.
