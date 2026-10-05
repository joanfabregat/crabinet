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
mv \
  "$state_dir/read-only/navigation-html.fixture" \
  "$state_dir/read-only/navigation.html"
mv \
  "$state_dir/read-only/hostile-svg.fixture" \
  "$state_dir/read-only/hostile.svg"
# A synthetic log above the 256 KiB preview limit: 6,000 lines of 52 bytes.
awk 'BEGIN { for (i = 1; i <= 6000; i++) printf "2026-01-01T00:00:00Z entry %05d synthetic log line\n", i }' \
  >"$state_dir/read-only/server.log"
# Synthetic HTML (294 kB) and SVG (437 kB) above the preview limit and within
# the 1 MiB render limit, and HTML (1.15 MB) above the render limit.
awk 'BEGIN { print "<!doctype html><title>Large page</title>"; for (i = 1; i <= 6000; i++) printf "<p>synthetic paragraph %05d of a large page</p>\n", i; print "<p id=\"last\">End of the large page</p>" }' \
  >"$state_dir/read-only/large.html"
awk 'BEGIN { for (i = 1; i <= 24000; i++) printf "<p>synthetic paragraph %05d of a huge page</p>\n", i }' \
  >"$state_dir/read-only/huge.html"
awk 'BEGIN { print "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"320\" height=\"200\">"; for (i = 1; i <= 8000; i++) printf "<rect x=\"%d\" y=\"0\" width=\"1\" height=\"1\" fill=\"none\"/>\n", i % 320; print "<circle cx=\"160\" cy=\"100\" r=\"80\" fill=\"teal\"/></svg>" }' \
  >"$state_dir/read-only/large.svg"
cp -R "$script_dir/fixtures/writable" "$state_dir/writable"
printf '%s' 'crabinet-e2e-only-session-secret-000000000000000000000000' >"$state_dir/session.key"
chmod 600 "$state_dir/session.key"

sed \
  -e "s|__STATE_DIR__|$state_dir|g" \
  -e "s|__PORT__|$port|g" \
  "$script_dir/fixtures/config.toml.in" >"$state_dir/config.toml"
chmod 600 "$state_dir/config.toml"

"$binary" --config "$state_dir/config.toml" &
server_pid=$!
wait "$server_pid"
