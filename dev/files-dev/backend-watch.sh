#!/bin/bash

set -euo pipefail

cd /workspace

fingerprint() {
  {
    stat --printf='%Y %s %n\n' Cargo.toml Cargo.lock
    find src tests -type f -name '*.rs' -printf '%T@ %s %p\n'
  } | sort | sha256sum | cut -d ' ' -f 1
}

app_pid=
stop_app() {
  if [[ -n "$app_pid" ]] && kill -0 "$app_pid" 2>/dev/null; then
    kill -TERM "$app_pid"
    wait "$app_pid" || true
  fi
}
trap stop_app EXIT
trap 'stop_app; exit 0' INT TERM

verify_lock() {
  local expected_lock actual_lock
  expected_lock=$(tr -d '[:space:]' < /etc/index-dev/Cargo.lock.sha256)
  actual_lock=$(sha256sum Cargo.lock | cut -d ' ' -f 1)
  if [[ "$actual_lock" != "$expected_lock" ]]; then
    echo "Cargo.lock changed; audit it and update dev/files-dev/Cargo.lock.sha256 before restarting index-dev-backend" >&2
    return 1
  fi
}

build_current_source() {
  local before after
  while true; do
    verify_lock
    before=$(fingerprint)
    if cargo build --locked; then
      after=$(fingerprint)
      if [[ "$before" == "$after" ]]; then
        return 0
      fi
      continue
    fi

    echo "Rust build failed; the last good backend remains available while waiting for another source change" >&2
    after=$(fingerprint)
    while [[ "$(fingerprint)" == "$after" ]]; do
      sleep 1
    done
  done
}

start_app() {
  /workspace/target/debug/index --config /etc/index/config.toml &
  app_pid=$!
}

build_current_source
start_app
running_fingerprint=$(fingerprint)

while true; do
  sleep 1
  if ! kill -0 "$app_pid" 2>/dev/null; then
    wait "$app_pid" || true
    echo "Rust backend exited unexpectedly" >&2
    exit 1
  fi

  current=$(fingerprint)
  if [[ "$current" != "$running_fingerprint" ]]; then
    build_current_source
    stop_app
    app_pid=
    start_app
    running_fingerprint=$(fingerprint)
  fi
done
