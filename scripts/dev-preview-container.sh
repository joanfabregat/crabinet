#!/bin/sh
# Runs only inside the attached, constrained development container.
set -eu

repo_root=/workspace
fixtures=$repo_root/web/e2e/fixtures
state_dir=$(mktemp -d /tmp/crabinet-preview.XXXXXXXX)
backend_pid=
vite_pid=

cleanup() {
  trap - EXIT INT TERM HUP
  for pid in "$vite_pid" "$backend_pid"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf -- "$state_dir"
}
trap cleanup EXIT INT TERM HUP

cp -R "$fixtures/read-only" "$state_dir/read-only"
mv "$state_dir/read-only/hostile-html.fixture" "$state_dir/read-only/hostile.html"
cp -R "$fixtures/writable" "$state_dir/writable"
head -c 48 /dev/urandom > "$state_dir/session.key"
chmod 600 "$state_dir/session.key"
sed \
  -e "s|__STATE_DIR__|$state_dir|g" \
  -e 's|__PORT__|8080|g' \
  -e 's|session_idle_timeout_seconds = 60|session_idle_timeout_seconds = 3600|g' \
  -e 's|session_absolute_timeout_seconds = 300|session_absolute_timeout_seconds = 28800|g' \
  "$fixtures/config.toml.in" > "$state_dir/config.toml"

# Land preview users in the synthetic writable share so create actions are visible.
awk '
  function finish_share() {
    if (share_id == "writable") writable_share = share_block
    else other_shares = other_shares share_block
    share_block = ""
  }
  /^\[\[shares\]\]$/ {
    finish_share()
    share_block = $0 ORS
    share_id = ""
    next
  }
  share_block != "" {
    share_block = share_block $0 ORS
    if ($0 == "id = \"writable\"") share_id = "writable"
    next
  }
  { print }
  END {
    finish_share()
    printf "%s%s", writable_share, other_shares
  }
' "$state_dir/config.toml" > "$state_dir/ordered-config.toml"
mv "$state_dir/ordered-config.toml" "$state_dir/config.toml"

if [ -d /run/crabinet-oidc ]; then
  awk '
    function grant(user, permission) {
      print ""
      print "[[shares.grants]]"
      print "user = \"" user "\""
      print "permission = \"" permission "\""
    }
    function add_grants() {
      if (share == "read-only") {
        grant("joan", "read")
        grant("kelly", "read")
      } else if (share == "writable") {
        grant("joan", "write")
        grant("kelly", "write")
      }
    }
    BEGIN {
      if ((getline joan_email < "/run/crabinet-oidc/joan-email") <= 0 ||
          (getline kelly_email < "/run/crabinet-oidc/kelly-email") <= 0 ||
          joan_email !~ /^[[:alnum:]._%+-]+@[[:alnum:].-]+$/ ||
          kelly_email !~ /^[[:alnum:]._%+-]+@[[:alnum:].-]+$/) exit 1
    }
    $0 == "[[shares]]" {
      add_grants()
      if (!users_added) {
        print ""
        print "[[users]]"
        print "username = \"joan\""
        print "email = \"" joan_email "\""
        print ""
        print "[[users]]"
        print "username = \"kelly\""
        print "email = \"" kelly_email "\""
        users_added = 1
      }
      share = ""
    }
    $0 == "id = \"read-only\"" { share = "read-only" }
    $0 == "id = \"writable\"" { share = "writable" }
    { print }
    END { add_grants() }
  ' "$state_dir/config.toml" > "$state_dir/oidc-config.toml"
  mv "$state_dir/oidc-config.toml" "$state_dir/config.toml"
  cat >> "$state_dir/config.toml" <<EOF

[auth]
password_enabled = true
oidc_enabled = true

[auth.oidc]
issuer = "https://accounts.google.com"
client_id = "$(cat /run/crabinet-oidc/client-id)"
client_secret_file = "/run/crabinet-oidc/client-secret"
redirect_uri = "https://files-dev.jf.ffwip.com/api/v1/auth/oidc/callback"
EOF
fi

export RUST_LOG=crabinet=debug
binary=$repo_root/target/debug/crabinet
"$binary" --config "$state_dir/config.toml" &
backend_pid=$!
running_binary=$(stat -c '%Y %s' "$binary")

export CRABINET_DEV_BACKEND_URL=http://127.0.0.1:8080
export CRABINET_DEV_PUBLIC_HOST=files-dev.jf.ffwip.com
export CRABINET_DEV_GIT_DIR=/workspace/.git
export CRABINET_VITE_CACHE_DIR=/tmp/vite-cache
cd "$repo_root/web"
./node_modules/.bin/vite --configLoader runner --host 0.0.0.0 --port 5173 &
vite_pid=$!

while kill -0 "$backend_pid" 2>/dev/null && kill -0 "$vite_pid" 2>/dev/null; do
  current_binary=$(stat -c '%Y %s' "$binary" 2>/dev/null || true)
  if [ -n "$current_binary" ] && [ "$current_binary" != "$running_binary" ]; then
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    "$binary" --config "$state_dir/config.toml" &
    backend_pid=$!
    running_binary=$current_binary
  fi
  sleep 1
done
echo 'A development preview process exited.' >&2
exit 1
