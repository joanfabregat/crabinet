#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

test "$(sha256sum "$repo_root/Cargo.lock" | cut -d ' ' -f 1)" = \
  "$(tr -d '[:space:]' < "$repo_root/dev/files-dev/Cargo.lock.sha256")"
test "$(sha256sum "$repo_root/web/package-lock.json" | cut -d ' ' -f 1)" = \
  "$(tr -d '[:space:]' < "$repo_root/dev/files-dev/package-lock.sha256")"

curl --fail --silent --show-error http://127.0.0.1:18082/health/ready >/dev/null
curl --fail --silent --show-error http://127.0.0.1:18081/health/ready >/dev/null
curl --fail --silent --show-error https://files-dev.jf.ffwip.com/health/ready >/dev/null
curl --fail --silent --show-error https://files-dev.jf.ffwip.com/@vite/client >/dev/null
curl --fail --silent --show-error https://files-dev.jf.ffwip.com/ \
  | grep -F '/@vite/client' >/dev/null
curl --fail --silent --show-error https://files-dev.jf.ffwip.com/src/app.tsx >/dev/null
curl --fail --silent --show-error \
  https://files-dev.jf.ffwip.com/src/highlighted-code.tsx >/dev/null

echo "Index development preview is ready and serving the Vite HMR client."
