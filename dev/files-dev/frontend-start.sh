#!/bin/sh

set -eu

expected_lock=$(tr -d '[:space:]' < /etc/index-dev/package-lock.sha256)
actual_lock=$(sha256sum /workspace/package-lock.json | cut -d ' ' -f 1)
if [ "$actual_lock" != "$expected_lock" ]; then
  echo "package-lock.json changed; audit dependencies, update dev/files-dev/package-lock.sha256, and refresh the preview node_modules before restarting index-dev" >&2
  exit 1
fi

exec /workspace/node_modules/.bin/vite \
  --configLoader runner \
  --host 0.0.0.0 \
  --port 5173
