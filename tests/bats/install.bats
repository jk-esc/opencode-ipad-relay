#!/usr/bin/env bats
# Hermetic tests for install.sh / uninstall.sh.
#
# Strategy: run the installer with HOME pointed at a fresh temp dir and a stub
# `opencode` on PATH, so nothing touches the real user setup or requires the
# real opencode binary. The installer is idempotent; several tests assert that.

setup() {
  export REAL_HOME="$HOME"
  export TEST_HOME
  TEST_HOME="$(mktemp -d)"
  export HOME="$TEST_HOME"

  export REPO_ROOT
  REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"

  # Stub toolchain: opencode is not expected on CI/dev machines under test.
  export STUB_BIN
  STUB_BIN="$(mktemp -d)"
  cat >"$STUB_BIN/opencode" <<'EOF'
#!/bin/bash
exit 0
EOF
  chmod +x "$STUB_BIN/opencode"
  export PATH="$STUB_BIN:$PATH"

  # Convenience paths the installer uses.
  export DATA_DIR="$TEST_HOME/.local/share/opencode-web"
  export BIN_DIR="$TEST_HOME/.local/bin"
  export PASSWORD_FILE="$DATA_DIR/password"
  export CERT_FILE="$DATA_DIR/cert.pem"
  export KEY_FILE="$DATA_DIR/key.pem"
}

teardown() {
  export HOME="$REAL_HOME"
  rm -rf "$TEST_HOME" "$STUB_BIN"
}

# --- assertion helpers --------------------------------------------------------
#
# bats runs under /bin/bash 3.2 on macOS, where `set -e` does NOT exit on a
# failing `[[ ... ]]` (and the ERR trap does not fire either). A `[[` assertion
# therefore only counts if it is the very last command of a test. These helpers
# are plain functions, whose non-zero return *does* trip `set -e`.

assert_contains() { # assert_contains "$haystack" "$needle"
  case "$1" in
  *"$2"*) return 0 ;;
  esac
  echo "assert_contains: expected to find [$2] in:" >&2
  echo "$1" >&2
  return 1
}

assert_not_contains() { # assert_not_contains "$haystack" "$needle"
  case "$1" in
  *"$2"*)
    echo "assert_not_contains: did not expect [$2] in:" >&2
    echo "$1" >&2
    return 1
    ;;
  esac
  return 0
}

run_install() {
  printf '%s\n' "$@" | "$REPO_ROOT/install.sh"
}

@test "fresh install creates password, cert, key and scripts" {
  run run_install "secret-pw" "secret-pw"
  [ "$status" -eq 0 ]
  [ -f "$PASSWORD_FILE" ]
  [ -f "$CERT_FILE" ]
  [ -f "$KEY_FILE" ]
  [ -x "$BIN_DIR/opencode-web" ]
  [ -x "$BIN_DIR/opencode-web-proxy.py" ]
}

@test "password file is mode 600 and contains the chosen password" {
  run run_install "secret-pw" "secret-pw"
  [ "$status" -eq 0 ]
  perms="$(stat -f '%Lp' "$PASSWORD_FILE")"
  [ "$perms" = "600" ]
  [ "$(cat "$PASSWORD_FILE")" = "secret-pw" ]
}

@test "private key is mode 600, cert is mode 644" {
  run run_install "secret-pw" "secret-pw"
  [ "$status" -eq 0 ]
  [ "$(stat -f '%Lp' "$KEY_FILE")" = "600" ]
  [ "$(stat -f '%Lp' "$CERT_FILE")" = "644" ]
}

@test "generated certificate is for opencode.local with SAN" {
  run run_install "secret-pw" "secret-pw"
  [ "$status" -eq 0 ]
  subject="$(openssl x509 -in "$CERT_FILE" -noout -subject)"
  assert_contains "$subject" "opencode.local"
  san="$(openssl x509 -in "$CERT_FILE" -noout -ext subjectAltName)"
  assert_contains "$san" "opencode.local"
}

@test "installer is idempotent: re-run keeps files, no re-prompt" {
  run run_install "secret-pw" "secret-pw"
  [ "$status" -eq 0 ]
  cert_before="$(shasum "$CERT_FILE")"
  pw_before="$(shasum "$PASSWORD_FILE")"

  # Second run with different piped input must NOT change anything.
  run run_install "different" "different"
  [ "$status" -eq 0 ]
  assert_contains "$output" "password already set (kept)"
  assert_contains "$output" "certificate already exists (kept)"
  [ "$(shasum "$CERT_FILE")" = "$cert_before" ]
  [ "$(shasum "$PASSWORD_FILE")" = "$pw_before" ]
}

@test "mismatched passwords are rejected and re-prompted" {
  run run_install "one" "two" "three" "three"
  [ "$status" -eq 0 ]
  assert_contains "$output" "passwords do not match"
  [ "$(cat "$PASSWORD_FILE")" = "three" ]
}

@test "empty password is rejected" {
  run run_install "" "valid" "valid"
  [ "$status" -eq 0 ]
  assert_contains "$output" "password cannot be empty"
  [ "$(cat "$PASSWORD_FILE")" = "valid" ]
}

@test "launcher errors clearly when password file is missing" {
  # Install scripts but not password: create scripts via a full install, then
  # delete the password file and invoke the launcher directly.
  run run_install "secret-pw" "secret-pw"
  [ "$status" -eq 0 ]
  rm -f "$PASSWORD_FILE"
  run "$BIN_DIR/opencode-web"
  [ "$status" -ne 0 ]
  assert_contains "$output" "run install.sh first"
}

@test "uninstall removes scripts but keeps data dir when answered 'n'" {
  run run_install "secret-pw" "secret-pw"
  [ "$status" -eq 0 ]
  run bash -c "printf 'n\n' | HOME='$TEST_HOME' '$REPO_ROOT/uninstall.sh'"
  [ "$status" -eq 0 ]
  [ ! -f "$BIN_DIR/opencode-web" ]
  [ ! -f "$BIN_DIR/opencode-web-proxy.py" ]
  [ -d "$DATA_DIR" ]
  [ -f "$PASSWORD_FILE" ]
}

@test "uninstall removes data dir when answered 'y'" {
  run run_install "secret-pw" "secret-pw"
  [ "$status" -eq 0 ]
  run bash -c "printf 'y\n' | HOME='$TEST_HOME' '$REPO_ROOT/uninstall.sh'"
  [ "$status" -eq 0 ]
  [ ! -f "$BIN_DIR/opencode-web" ]
  [ ! -d "$DATA_DIR" ]
}

# --- launcher ---------------------------------------------------------------
#
# The launcher is exercised with stubs so no real server ever binds a port:
#   opencode   -> records its argv to $HOME/opencode.args and exits
#   caffeinate -> execs the wrapped utility (drops its own flags)
#   python3    -> no-op (the relay itself is covered by pytest)

stub_launcher_deps() {
  cat >"$STUB_BIN/opencode" <<'EOF2'
#!/bin/bash
printf '%s\n' "$@" >"$HOME/opencode.args"
exit 0
EOF2
  cat >"$STUB_BIN/caffeinate" <<'EOF2'
#!/bin/bash
while [ "${1#-}" != "$1" ]; do shift; done
exec "$@"
EOF2
  cat >"$STUB_BIN/python3" <<'EOF2'
#!/bin/bash
exit 0
EOF2
  chmod +x "$STUB_BIN/opencode" "$STUB_BIN/caffeinate" "$STUB_BIN/python3"
}

@test "launcher binds the backend to loopback only (no LAN-facing plain HTTP)" {
  run run_install "secret-pw" "secret-pw"
  [ "$status" -eq 0 ]
  stub_launcher_deps
  run "$BIN_DIR/opencode-web"
  [ -f "$HOME/opencode.args" ]
  args="$(tr '\n' ' ' <"$HOME/opencode.args")"
  assert_contains "$args" "--hostname 127.0.0.1"
  assert_not_contains "$args" "--mdns"
}

# mDNS stubs: route/ipconfig give a deterministic LAN IPv4; dns-sd records its
# argv and its own PID, then sleeps so the test can check it was cleaned up.
stub_mdns_deps() {
  cat >"$STUB_BIN/route" <<'EOF2'
#!/bin/bash
echo "   interface: en0"
EOF2
  cat >"$STUB_BIN/ipconfig" <<'EOF2'
#!/bin/bash
[ "$1" = "getifaddr" ] && [ "$2" = "en0" ] && echo "192.0.2.10" && exit 0
exit 1
EOF2
  cat >"$STUB_BIN/dns-sd" <<'EOF2'
#!/bin/bash
printf '%s\n' "$@" >"$HOME/dns-sd.args"
echo "$$" >"$HOME/dns-sd.pid"
sleep 60
EOF2
  chmod +x "$STUB_BIN/route" "$STUB_BIN/ipconfig" "$STUB_BIN/dns-sd"
}

@test "launcher advertises opencode.local via dns-sd with the LAN IPv4" {
  run run_install "secret-pw" "secret-pw"
  [ "$status" -eq 0 ]
  stub_launcher_deps
  stub_mdns_deps
  run "$BIN_DIR/opencode-web"
  [ -f "$HOME/dns-sd.args" ]
  args="$(tr '\n' ' ' <"$HOME/dns-sd.args")"
  assert_contains "$args" "-P opencode _https._tcp local 443 opencode.local 192.0.2.10"
}

@test "launcher stops the dns-sd advertisement when it exits" {
  run run_install "secret-pw" "secret-pw"
  [ "$status" -eq 0 ]
  stub_launcher_deps
  stub_mdns_deps
  run "$BIN_DIR/opencode-web"
  [ -f "$HOME/dns-sd.pid" ]
  pid="$(cat "$HOME/dns-sd.pid")"
  sleep 0.5
  ! kill -0 "$pid" 2>/dev/null
}

@test "launcher still starts, with a warning, when the LAN IPv4 cannot be determined" {
  run run_install "secret-pw" "secret-pw"
  [ "$status" -eq 0 ]
  stub_launcher_deps
  stub_mdns_deps
  printf '#!/bin/bash\nexit 1\n' >"$STUB_BIN/ipconfig"
  run "$BIN_DIR/opencode-web"
  [ "$status" -eq 0 ]
  [ -f "$HOME/opencode.args" ]
  [ ! -f "$HOME/dns-sd.args" ]
  assert_contains "$output" "warning"
  assert_contains "$output" ".local"
}
