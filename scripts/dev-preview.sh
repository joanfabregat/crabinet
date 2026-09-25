#!/usr/bin/env bash
# Keep the routed development preview attached to this shell session.
set -euo pipefail

require-dev-vm

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test -x "$repo_root/target/debug/crabinet" || {
  echo "Build the debug binary with the constrained Rust runner first." >&2
  exit 1
}
test -x "$repo_root/web/node_modules/.bin/vite" || {
  echo "Install and audit the locked frontend dependencies in the constrained Node runner first." >&2
  exit 1
}

unit_base="crabinet-preview-$(id -u)-${BASHPID}-${RANDOM}"
container_name="$unit_base"
image='docker.io/library/node:24-bookworm-slim@sha256:713cfbf4a0ac19f40e1bb9919893e126b74a5c8cf5d0623c9f89515c8f74c6fa'
oidc_dir=/home/joan/.local/state/crabinet-preview/oidc
oidc_mount=()
if [ -d "$oidc_dir" ]; then
  for file in client-id client-secret joan-email kelly-email joan-permission kelly-permission; do
    test -s "$oidc_dir/$file" || {
      echo "Incomplete development OIDC credentials: missing $file." >&2
      exit 1
    }
  done
  oidc_mount=(--volume="$oidc_dir:/run/crabinet-oidc:ro,rprivate")
fi

cleanup() {
  trap - EXIT INT TERM HUP
  sudo systemctl stop "$unit_base.service" >/dev/null 2>&1 || true
  podman rm --force "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM HUP

sudo systemd-run --quiet --wait --pipe --collect \
  --unit="$unit_base" \
  --description='Attached Crabinet development preview' \
  --service-type=exec \
  --uid=joan --gid=joan \
  --setenv=HOME=/home/joan \
  --setenv=XDG_RUNTIME_DIR=/run/user/1001 \
  --property=KillMode=control-group \
  --property=TimeoutStopSec=20s \
  --property=RuntimeMaxSec=2h \
  --property=MemoryMax=4G \
  --property=MemorySwapMax=4G \
  --property=CPUQuota=200% \
  --property=TasksMax=512 \
  --property=OOMPolicy=kill \
  --property=UMask=0077 \
  --property=IPAddressDeny=169.254.0.0/16 \
  --property=IPAddressDeny=fd20:ce::254/128 \
  /usr/bin/podman run --rm --interactive \
    --name="$container_name" \
    --cgroups=disabled \
    --pull=missing \
    --network=bridge \
    --dns=1.1.1.1 --dns=1.0.0.1 \
    --userns=keep-id \
    --user="$(id -u):$(id -g)" \
    --read-only --read-only-tmpfs=false \
    --tmpfs=/tmp:rw,nosuid,nodev,size=512m,mode=1777 \
    --tmpfs=/run:rw,nosuid,nodev,size=64m,mode=0755 \
    --cap-drop=all \
    --security-opt=no-new-privileges \
    --hostname=sandbox \
    --stop-timeout=10 \
    --volume="$repo_root:/workspace:ro,rprivate" \
    "${oidc_mount[@]}" \
    --workdir=/workspace \
    --publish=127.0.0.1:18081:5173 \
    --env=HOME=/tmp \
    --env=TMPDIR=/tmp \
    --label=traefik.enable=true \
    '--label=traefik.http.routers.crabinet-preview.rule=Host(`files-dev.jf.ffwip.com`)' \
    --label=traefik.http.routers.crabinet-preview.entrypoints=websecure \
    --label=traefik.http.routers.crabinet-preview.service=crabinet-preview \
    --label=traefik.http.services.crabinet-preview.loadbalancer.server.port=5173 \
    --label=traefik.http.services.crabinet-preview.loadbalancer.healthcheck.path=/health/ready \
    --label=traefik.http.services.crabinet-preview.loadbalancer.healthcheck.interval=10s \
    --label=traefik.http.services.crabinet-preview.loadbalancer.healthcheck.timeout=5s \
    "$image" \
    /bin/sh /workspace/scripts/dev-preview-container.sh
