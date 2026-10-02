#!/usr/bin/env bash
# Runs a Crabinet image with the hardening the README recommends, using the
# synthetic browser E2E fixtures, and checks that it:
#   - packages exactly the expected binary (threat-model invariant 14);
#   - becomes ready and serves one authenticated listing;
#   - refuses unauthenticated and ungranted listings;
#   - runs as a non-root user with no capabilities and no-new-privileges.
#
# Usage: container-smoke.sh IMAGE EXPECTED_BINARY
# Requires docker, curl, jq, and passwordless sudo (a GitHub-hosted runner).
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 IMAGE EXPECTED_BINARY" >&2
  exit 2
fi
image=$1
expected_binary=$2

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
fixtures="${script_dir}/../../web/e2e/fixtures"
user_id=65532
port=18080
base_url="http://127.0.0.1:${port}"
container="crabinet-smoke-$$"
probe="crabinet-smoke-probe-$$"
state=$(mktemp -d "${RUNNER_TEMP:-/tmp}/crabinet-smoke.XXXXXXXX")

cleanup() {
  local status=$?
  trap - EXIT
  if [[ ${status} -ne 0 ]] && docker container inspect "${container}" >/dev/null 2>&1; then
    echo "Container log tail:" >&2
    docker logs --tail 50 "${container}" >&2 || true
  fi
  docker rm --force "${container}" "${probe}" >/dev/null 2>&1 || true
  sudo rm -rf -- "${state}"
  exit "${status}"
}
trap cleanup EXIT

fail() {
  echo "Container smoke test failed: $*" >&2
  exit 1
}

# Invariant 14: the image's executable is byte-identical to the tested one.
docker create --name "${probe}" "${image}" >/dev/null
docker cp "${probe}:/crabinet" "${state}/image-crabinet"
docker rm "${probe}" >/dev/null
expected_sum=$(sha256sum "${expected_binary}" | cut -d' ' -f1)
image_sum=$(sha256sum "${state}/image-crabinet" | cut -d' ' -f1)
if [[ "${expected_sum}" != "${image_sum}" ]]; then
  fail "image binary ${image_sum} differs from expected binary ${expected_sum}"
fi
echo "Image binary matches the expected binary (sha256 ${image_sum})."

mkdir -p "${state}/config" "${state}/secrets" "${state}/data" "${state}/shares"
cp -R "${fixtures}/read-only" "${state}/shares/read-only"
mv "${state}/shares/read-only/hostile-html.fixture" "${state}/shares/read-only/hostile.html"
cp -R "${fixtures}/writable" "${state}/shares/writable"
printf '%s' 'crabinet-smoke-only-session-secret-0000000000000000000000' \
  >"${state}/secrets/session.key"
sed \
  -e "s|127.0.0.1:__PORT__|0.0.0.0:8080|" \
  -e "s|__STATE_DIR__/sessions.sqlite3|/var/lib/crabinet/sessions.sqlite3|" \
  -e "s|__STATE_DIR__/session.key|/run/secrets/crabinet/session.key|" \
  -e "s|__STATE_DIR__/|/srv/crabinet/|g" \
  "${fixtures}/config.toml.in" >"${state}/config/config.toml"
if grep -q '__[A-Z_]*__' "${state}/config/config.toml"; then
  fail "unreplaced placeholder in the generated configuration"
fi
chmod 0444 "${state}/config/config.toml"
chmod 0400 "${state}/secrets/session.key"
sudo chown -R "${user_id}:${user_id}" \
  "${state}/config" "${state}/secrets" "${state}/data" "${state}/shares"

docker run --detach --name "${container}" \
  --user "${user_id}:${user_id}" \
  --read-only \
  --cap-drop=all \
  --security-opt=no-new-privileges \
  --memory=256m \
  --pids-limit=256 \
  --publish "127.0.0.1:${port}:8080" \
  --volume "${state}/config/config.toml:/etc/crabinet/config.toml:ro" \
  --volume "${state}/secrets:/run/secrets/crabinet:ro" \
  --volume "${state}/data:/var/lib/crabinet:rw" \
  --volume "${state}/shares/read-only:/srv/crabinet/read-only:ro" \
  --volume "${state}/shares/writable:/srv/crabinet/writable:rw" \
  "${image}" \
  --config /etc/crabinet/config.toml >/dev/null

ready=false
for _ in $(seq 1 60); do
  if [[ "$(docker inspect --format '{{.State.Running}}' "${container}")" != true ]]; then
    fail "container exited before becoming ready"
  fi
  status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    "${base_url}/health/ready" || true)
  if [[ "${status}" == 200 ]]; then
    ready=true
    break
  fi
  sleep 1
done
[[ "${ready}" == true ]] || fail "/health/ready did not return 200 within 60 seconds"
echo "/health/ready returned 200."

# The process must run as the unprivileged image user with no capabilities.
pid=$(docker inspect --format '{{.State.Pid}}' "${container}")
proc_status=$(sudo cat "/proc/${pid}/status")
for field in Uid Gid; do
  ids=$(awk -v field="${field}:" '$1 == field { print $2, $3, $4, $5 }' <<<"${proc_status}")
  if [[ "${ids}" != "${user_id} ${user_id} ${user_id} ${user_id}" ]]; then
    fail "process ${field} is '${ids}', expected ${user_id} for every ID"
  fi
done
for field in CapPrm CapEff CapBnd CapAmb; do
  value=$(awk -v field="${field}:" '$1 == field { print $2 }' <<<"${proc_status}")
  [[ "${value}" =~ ^0+$ ]] || fail "process ${field} is ${value}, expected no capabilities"
done
no_new_privs=$(awk '$1 == "NoNewPrivs:" { print $2 }' <<<"${proc_status}")
[[ "${no_new_privs}" == 1 ]] || fail "process does not have no-new-privileges set"
echo "Process runs as ${user_id}:${user_id} with no capabilities and no-new-privileges."

anonymous=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "${base_url}/api/v1/shares/read-only/directory")
[[ "${anonymous}" == 401 ]] || fail "anonymous listing returned ${anonymous}, expected 401"

# Log in like the browser does: same-origin JSON with an Origin header.
curl --fail --silent --show-error \
  --dump-header "${state}/login.headers" \
  --output /dev/null \
  --header 'Content-Type: application/json' \
  --header "Origin: ${base_url}" \
  --header 'Sec-Fetch-Site: same-origin' \
  --data '{"username":"reader","password":"e2e-password"}' \
  "${base_url}/api/v1/auth/login"
cookie=$(tr -d '\r' <"${state}/login.headers" |
  sed -n 's/^[Ss]et-[Cc]ookie: \(__Host-crabinet_session=[^;]*\).*/\1/p' |
  head -n 1)
[[ -n "${cookie}" ]] || fail "login did not set a session cookie"

curl --fail --silent --show-error \
  --header "Cookie: ${cookie}" \
  --output "${state}/listing.json" \
  "${base_url}/api/v1/shares/read-only/directory"
jq --exit-status '.entries | map(.name) | index("Guide.md") != null' \
  "${state}/listing.json" >/dev/null ||
  fail "authenticated listing did not include the synthetic fixture"
echo "Authenticated listing returned the synthetic fixture."

ungranted=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header "Cookie: ${cookie}" \
  "${base_url}/api/v1/shares/writable/directory")
[[ "${ungranted}" != 200 ]] || fail "reader listed a share without a grant"

echo "Container smoke test passed."
