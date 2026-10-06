#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
binary=${CRABINET_E2E_BINARY:-"$repo_root/target/release/crabinet"}
port=${CRABINET_E2E_PORT:-4173}
# With CRABINET_E2E_TLS=1, the server listens 100 ports higher and a TLS
# proxy (tls-proxy.ts) serves it on CRABINET_E2E_PORT, as a reverse proxy
# does in production.
tls=${CRABINET_E2E_TLS:-0}
listen_port=$port
if [ "$tls" = 1 ]; then
  listen_port=$((port + 100))
fi
# With CRABINET_E2E_OIDC=1 (which needs CRABINET_E2E_TLS=1), OIDC sign-in is
# enabled alongside passwords, against a fake provider (fake-oidc.ts) on the
# port 200 higher that only a per-run test CA, given as auth.oidc.ca_file,
# vouches for.
oidc=${CRABINET_E2E_OIDC:-0}
if [ "$oidc" = 1 ] && [ "$tls" != 1 ]; then
  echo "CRABINET_E2E_OIDC=1 needs CRABINET_E2E_TLS=1: the callback is HTTPS" >&2
  exit 1
fi

if [ ! -x "$binary" ]; then
  echo "E2E production binary not found at $binary" >&2
  echo "Build web assets, then run: cargo build --locked --release" >&2
  exit 1
fi

state_dir=$(mktemp -d "${TMPDIR:-/tmp}/crabinet-e2e.XXXXXXXX")
server_pid=
proxy_pid=
provider_pid=

cleanup() {
  trap - EXIT INT TERM
  for pid in $proxy_pid $server_pid $provider_pid; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
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
  -e "s|__PORT__|$listen_port|g" \
  "$script_dir/fixtures/config.toml.in" >"$state_dir/config.toml"
if [ "$oidc" = 1 ]; then
  # The fake provider (fake-oidc.ts) serves HTTPS with a certificate from a
  # test CA made for this run. Crabinet trusts that CA only through
  # auth.oidc.ca_file; the CA's key is deleted once the certificate is signed.
  provider_port=$((port + 200))
  public_origin="https://localhost:$port"
  cat >"$state_dir/oidc-pki.cnf" <<'PKI'
[req]
distinguished_name = dn
[dn]
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[provider]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1,DNS:localhost
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
PKI
  openssl req -x509 -new -config "$state_dir/oidc-pki.cnf" -extensions ca \
    -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj "/CN=Crabinet E2E test CA" \
    -keyout "$state_dir/oidc-ca.key" -out "$state_dir/oidc-ca.crt" 2>/dev/null
  openssl req -new -config "$state_dir/oidc-pki.cnf" \
    -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj /CN=127.0.0.1 \
    -keyout "$state_dir/oidc-provider.key" -out "$state_dir/oidc-provider.csr" 2>/dev/null
  openssl x509 -req -in "$state_dir/oidc-provider.csr" \
    -CA "$state_dir/oidc-ca.crt" -CAkey "$state_dir/oidc-ca.key" \
    -set_serial "0x$(openssl rand -hex 8)" -days 1 \
    -extfile "$state_dir/oidc-pki.cnf" -extensions provider \
    -out "$state_dir/oidc-provider.crt" 2>/dev/null
  rm -f -- "$state_dir/oidc-ca.key" "$state_dir/oidc-provider.csr"
  chmod 644 "$state_dir/oidc-ca.crt"
  (umask 077 && openssl rand -hex 32 | tr -d '\n' >"$state_dir/oidc-client.secret")

  node "$script_dir/fake-oidc.ts" "$provider_port" \
    "$state_dir/oidc-provider.crt" "$state_dir/oidc-provider.key" \
    crabinet-e2e "$state_dir/oidc-client.secret" \
    "$public_origin/api/v1/auth/oidc/callback" "$state_dir/oidc-ready" &
  provider_pid=$!
  # Crabinet reads discovery at startup, so the provider must be up first.
  attempts=0
  while [ ! -e "$state_dir/oidc-ready" ]; do
    attempts=$((attempts + 1))
    if [ "$attempts" -gt 100 ] || ! kill -0 "$provider_pid" 2>/dev/null; then
      echo "The fake OIDC provider did not start" >&2
      exit 1
    fi
    sleep 0.1
  done

  cat >>"$state_dir/config.toml" <<OIDC

[auth]
oidc_enabled = true

[auth.oidc]
issuer = "https://127.0.0.1:$provider_port"
client_id = "crabinet-e2e"
client_secret_file = "$state_dir/oidc-client.secret"
redirect_uri = "$public_origin/api/v1/auth/oidc/callback"
ca_file = "$state_dir/oidc-ca.crt"
OIDC
fi

chmod 600 "$state_dir/config.toml"

"$binary" --config "$state_dir/config.toml" &
server_pid=$!

if [ "$tls" = 1 ]; then
  # A throwaway certificate for this run only; Playwright ignores its issuer.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -days 1 -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
    -keyout "$state_dir/tls.key" -out "$state_dir/tls.crt" 2>/dev/null
  node "$script_dir/tls-proxy.ts" "$port" "$listen_port" \
    "$state_dir/tls.crt" "$state_dir/tls.key" &
  proxy_pid=$!
fi

wait "$server_pid"
