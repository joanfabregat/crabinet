#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
binary=${CRABINET_E2E_BINARY:-"$repo_root/target/release/crabinet"}
port=${CRABINET_E2E_PORT:-4173}

if [ ! -x "$binary" ]; then
  echo "E2E production binary not found at $binary" >&2
  echo "Build web assets, then run: cargo build --locked --release" >&2
  exit 1
fi

state_dir=$(mktemp -d "${TMPDIR:-/tmp}/crabinet-e2e.XXXXXXXX")
server_pid=

cleanup() {
  trap - EXIT INT TERM
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf -- "$state_dir"
}
trap cleanup EXIT INT TERM

cp -R "$script_dir/fixtures/read-only" "$state_dir/read-only"
mv \
  "$state_dir/read-only/hostile-html.fixture" \
  "$state_dir/read-only/hostile.html"
cp -R "$script_dir/fixtures/writable" "$state_dir/writable"
printf '%s' 'crabinet-e2e-only-session-secret-000000000000000000000000' >"$state_dir/session.key"
chmod 600 "$state_dir/session.key"

sed \
  -e "s|__STATE_DIR__|$state_dir|g" \
  -e "s|__PORT__|$port|g" \
  "$script_dir/fixtures/config.toml.in" >"$state_dir/config.toml"

"$binary" --config "$state_dir/config.toml" &
server_pid=$!
wait "$server_pid"
