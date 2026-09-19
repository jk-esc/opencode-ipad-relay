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

# Generating the real 4096-bit key takes seconds, and most tests only need
# the installer to get past that step. Make one cheap certificate per suite
# and drop it in; the tests that actually inspect the certificate skip this
# and let the installer generate a real one.
seed_cert() {
  local cache="$BATS_SUITE_TMPDIR/seed-cert"
  if [ ! -f "$cache/cert.pem" ]; then
    mkdir -p "$cache"
    # Same shape as the one the installer makes, so a seeded install looks
    # like an up-to-date one; only the key size and lifetime differ.
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$cache/key.pem" -out "$cache/cert.pem" -days 30 \
      -subj "/CN=opencode.local" \
      -addext "subjectAltName=DNS:opencode.local,DNS:$(scutil --get LocalHostName).local" \
      -addext "extendedKeyUsage=serverAuth" \
      -addext "keyUsage=digitalSignature,keyEncipherment" \
      -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
  fi
  mkdir -p "$DATA_DIR"
  chmod 700 "$DATA_DIR"
  cp "$cache/cert.pem" "$cache/key.pem" "$DATA_DIR/"
  chmod 600 "$DATA_DIR/key.pem"
  chmod 644 "$DATA_DIR/cert.pem"
}

# Default: the installer generates the password and must not read stdin.
# </dev/null keeps a regression here as a fast failure rather than a hang.
run_install() {
  "$REPO_ROOT/install.sh" </dev/null
}

# --password: the installer prompts, so feed it the answers.
run_install_pw() {
  printf '%s\n' "$@" | "$REPO_ROOT/install.sh" --password
}

@test "fresh install creates password, cert, key and scripts" {
  run run_install
  [ "$status" -eq 0 ]
  [ -f "$PASSWORD_FILE" ]
  [ -f "$CERT_FILE" ]
  [ -f "$KEY_FILE" ]
  [ -x "$BIN_DIR/opencode-web" ]
  [ -x "$BIN_DIR/opencode-web-proxy.py" ]
}

@test "password file is mode 600 and contains the chosen password" {
  seed_cert
  run run_install_pw "correct horse" "correct horse"
  [ "$status" -eq 0 ]
  perms="$(stat -f '%Lp' "$PASSWORD_FILE")"
  [ "$perms" = "600" ]
  [ "$(cat "$PASSWORD_FILE")" = "correct horse" ]
}

@test "private key is mode 600, cert is mode 644" {
  run run_install
  [ "$status" -eq 0 ]
  [ "$(stat -f '%Lp' "$KEY_FILE")" = "600" ]
  [ "$(stat -f '%Lp' "$CERT_FILE")" = "644" ]
}

@test "generated certificate is for opencode.local with SAN" {
  run run_install
  [ "$status" -eq 0 ]
  subject="$(openssl x509 -in "$CERT_FILE" -noout -subject)"
  assert_contains "$subject" "opencode.local"
  san="$(openssl x509 -in "$CERT_FILE" -noout -ext subjectAltName)"
  assert_contains "$san" "opencode.local"
}

@test "installer is idempotent: re-run keeps files, no re-prompt" {
  seed_cert
  run run_install
  [ "$status" -eq 0 ]
  cert_before="$(shasum "$CERT_FILE")"
  pw_before="$(shasum "$PASSWORD_FILE")"

  # Second run with different piped input must NOT change anything.
  run run_install
  [ "$status" -eq 0 ]
  assert_contains "$output" "password already set (kept)"
  assert_contains "$output" "certificate already exists (kept)"
  [ "$(shasum "$CERT_FILE")" = "$cert_before" ]
  [ "$(shasum "$PASSWORD_FILE")" = "$pw_before" ]
}

@test "mismatched passwords are rejected and re-prompted" {
  seed_cert
  run run_install_pw "one two three" "four five six" "one two three" "one two three"
  [ "$status" -eq 0 ]
  assert_contains "$output" "passwords do not match"
  [ "$(cat "$PASSWORD_FILE")" = "one two three" ]
}

@test "empty password is rejected" {
  seed_cert
  run run_install_pw "" "long enough pw" "long enough pw"
  [ "$status" -eq 0 ]
  assert_contains "$output" "password cannot be empty"
  [ "$(cat "$PASSWORD_FILE")" = "long enough pw" ]
}

@test "launcher errors clearly when password file is missing" {
  seed_cert
  # Install scripts but not password: create scripts via a full install, then
  # delete the password file and invoke the launcher directly.
  run run_install
  [ "$status" -eq 0 ]
  rm -f "$PASSWORD_FILE"
  run "$BIN_DIR/opencode-web"
  [ "$status" -ne 0 ]
  assert_contains "$output" "run install.sh first"
}

@test "uninstall removes scripts but keeps data dir when answered 'n'" {
  seed_cert
  run run_install
  [ "$status" -eq 0 ]
  run bash -c "printf 'n\n' | HOME='$TEST_HOME' '$REPO_ROOT/uninstall.sh'"
  [ "$status" -eq 0 ]
  [ ! -f "$BIN_DIR/opencode-web" ]
  [ ! -f "$BIN_DIR/opencode-web-proxy.py" ]
  [ -d "$DATA_DIR" ]
  [ -f "$PASSWORD_FILE" ]
}

@test "uninstall removes data dir when answered 'y'" {
  seed_cert
  run run_install
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
exec >/dev/null 2>&1
exec sleep 60
EOF2
  # The fake backend counts as listening only once it has really started,
  # so the launcher's readiness loop can't race ahead of it. The first call
  # always says "not yet", which forces one turn of the loop and gives
  # anything else the launcher backgrounded a chance to run.
  cat >"$STUB_BIN/lsof" <<'EOF2'
#!/bin/bash
[ -f "$HOME/opencode.args" ] || exit 1
[ -f "$HOME/lsof.polled" ] || { : >"$HOME/lsof.polled"; exit 1; }
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
  chmod +x "$STUB_BIN/opencode" "$STUB_BIN/lsof" "$STUB_BIN/caffeinate" "$STUB_BIN/python3"
}

@test "launcher binds the backend to loopback only (no LAN-facing plain HTTP)" {
  seed_cert
  run run_install
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
exec >/dev/null 2>&1
exec sleep 60
EOF2
  chmod +x "$STUB_BIN/route" "$STUB_BIN/ipconfig" "$STUB_BIN/dns-sd"
}

@test "launcher advertises opencode.local via dns-sd with the LAN IPv4" {
  seed_cert
  run run_install
  [ "$status" -eq 0 ]
  stub_launcher_deps
  stub_mdns_deps
  run "$BIN_DIR/opencode-web"
  [ -f "$HOME/dns-sd.args" ]
  args="$(tr '\n' ' ' <"$HOME/dns-sd.args")"
  assert_contains "$args" "-P opencode _https._tcp local 443 opencode.local 192.0.2.10"
}

@test "launcher stops the dns-sd advertisement when it exits" {
  seed_cert
  run run_install
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
  seed_cert
  run run_install
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

# --- launcher lifecycle -------------------------------------------------------

assert_dead() {
  if kill -0 "$1" 2>/dev/null; then
    echo "process $1 is still alive" >&2
    return 1
  fi
}

@test "launcher records the PIDs of everything it starts" {
  seed_cert
  run run_install
  [ "$status" -eq 0 ]
  stub_launcher_deps
  stub_mdns_deps
  printf '#!/bin/bash\nexec sleep 60\n' >"$STUB_BIN/python3"
  "$BIN_DIR/opencode-web" >/dev/null 2>&1 &
  LAUNCHER_PID=$!
  for _ in $(seq 1 25); do
    [ -f "$DATA_DIR/run.pid" ] && break
    sleep 0.2
  done
  [ -f "$DATA_DIR/run.pid" ]
  # launcher itself plus opencode, dns-sd and the relay
  [ "$(wc -l <"$DATA_DIR/run.pid" | tr -d ' ')" -ge 3 ]
  kill "$LAUNCHER_PID" 2>/dev/null || true
  wait "$LAUNCHER_PID" 2>/dev/null || true
}

@test "kill -TERM on the launcher stops opencode, dns-sd and the relay" {
  seed_cert
  run run_install
  [ "$status" -eq 0 ]
  stub_launcher_deps
  stub_mdns_deps
  printf '#!/bin/bash\nexec sleep 60\n' >"$STUB_BIN/python3"
  "$BIN_DIR/opencode-web" >/dev/null 2>&1 &
  LAUNCHER_PID=$!
  for _ in $(seq 1 25); do
    [ -f "$DATA_DIR/run.pid" ] && break
    sleep 0.2
  done
  [ -f "$DATA_DIR/run.pid" ]
  pids="$(cat "$DATA_DIR/run.pid")"
  kill -TERM "$LAUNCHER_PID"
  sleep 1
  for p in $pids; do
    assert_dead "$p"
  done
  assert_dead "$LAUNCHER_PID"
  [ ! -f "$DATA_DIR/run.pid" ]
}

@test "launcher fails fast when opencode dies before it is ready" {
  seed_cert
  run run_install
  [ "$status" -eq 0 ]
  stub_launcher_deps
  stub_mdns_deps
  printf '#!/bin/bash\nexit 1\n' >"$STUB_BIN/opencode"
  printf '#!/bin/bash\nexit 1\n' >"$STUB_BIN/lsof"
  run "$BIN_DIR/opencode-web"
  [ "$status" -ne 0 ]
  assert_contains "$output" "opencode exited"
}

@test "launcher exits with the relay's status" {
  seed_cert
  run run_install
  [ "$status" -eq 0 ]
  stub_launcher_deps
  stub_mdns_deps
  printf '#!/bin/bash\nexit 7\n' >"$STUB_BIN/python3"
  run "$BIN_DIR/opencode-web"
  [ "$status" -eq 7 ]
}

@test "uninstall stops the processes listed in run.pid" {
  seed_cert
  run run_install
  [ "$status" -eq 0 ]
  sleep 60 >/dev/null 2>&1 &
  FAKE_PID=$!
  echo "$FAKE_PID" >"$DATA_DIR/run.pid"
  run bash -c "printf 'n\n' | HOME='$TEST_HOME' '$REPO_ROOT/uninstall.sh'"
  [ "$status" -eq 0 ]
  assert_dead "$FAKE_PID"
  [ ! -f "$DATA_DIR/run.pid" ]
}

@test "uninstall does not kill by process-name pattern" {
  seed_cert
  # pkill -f matches any command line containing the pattern, which can hit
  # an editor or pager that merely has the file open. The uninstaller must
  # only ever kill PIDs it recorded itself.
  run grep -cE '^[[:space:]]*[^#]*\bpkill\b' "$REPO_ROOT/uninstall.sh"
  [ "$output" = "0" ]
}

# --- password strength --------------------------------------------------------

@test "installer generates a strong password by default and shows it once" {
  seed_cert
  run run_install
  [ "$status" -eq 0 ]
  pw="$(cat "$PASSWORD_FILE")"
  [ "${#pw}" -ge 20 ]
  # Shown exactly once so it can be typed on the iPad.
  assert_contains "$output" "$pw"
  [ "$(grep -c -- "$pw" <<<"$output")" -eq 1 ]
}

@test "generated passwords differ between installs" {
  seed_cert
  run run_install
  [ "$status" -eq 0 ]
  first="$(cat "$PASSWORD_FILE")"
  rm -f "$PASSWORD_FILE"
  run run_install
  [ "$status" -eq 0 ]
  [ "$first" != "$(cat "$PASSWORD_FILE")" ]
}

@test "a chosen password under 12 characters is rejected" {
  seed_cert
  run run_install_pw "short" "short" "long enough pw" "long enough pw"
  [ "$status" -eq 0 ]
  assert_contains "$output" "at least 12"
  [ "$(cat "$PASSWORD_FILE")" = "long enough pw" ]
}

@test "a chosen password keeps its leading and trailing spaces" {
  seed_cert
  run run_install_pw "  spaces  kept  " "  spaces  kept  "
  [ "$status" -eq 0 ]
  [ "$(cat "$PASSWORD_FILE")" = "  spaces  kept  " ]
}

@test "asking for a password with no input fails loudly" {
  seed_cert
  run bash -c "HOME='$TEST_HOME' '$REPO_ROOT/install.sh' --password </dev/null"
  [ "$status" -ne 0 ]
  assert_contains "$output" "no password given"
  [ ! -f "$PASSWORD_FILE" ]
}

@test "an unknown flag is refused" {
  seed_cert
  run bash -c "HOME='$TEST_HOME' '$REPO_ROOT/install.sh' --nope"
  [ "$status" -ne 0 ]
  assert_contains "$output" "unknown option"
}

# --- certificate --------------------------------------------------------------
#
# Apple publishes rules for certificates iOS and macOS will trust
# (support.apple.com/103769): SHA-2, a DNS name in subjectAltName, an
# extendedKeyUsage of serverAuth, and at most 825 days. The old certificate
# met the first two and neither of the others.

@test "certificate carries the serverAuth purpose Apple asks for" {
  run run_install
  [ "$status" -eq 0 ]
  text="$(openssl x509 -in "$CERT_FILE" -noout -text)"
  assert_contains "$text" "TLS Web Server Authentication"
}

@test "certificate is valid for no more than 825 days" {
  run run_install
  [ "$status" -eq 0 ]
  # 826 days from now must be past its expiry.
  run openssl x509 -in "$CERT_FILE" -noout -checkend 71366400
  [ "$status" -ne 0 ]
  # ...but it should still be good for a year.
  run openssl x509 -in "$CERT_FILE" -noout -checkend 31536000
  [ "$status" -eq 0 ]
}

@test "certificate names this Mac as well as opencode.local" {
  run run_install
  [ "$status" -eq 0 ]
  san="$(openssl x509 -in "$CERT_FILE" -noout -ext subjectAltName)"
  assert_contains "$san" "DNS:opencode.local"
  assert_contains "$san" "DNS:$(scutil --get LocalHostName).local"
}

@test "certificate has no IP address in it" {
  # It used to pin whatever en0 happened to be, which is wrong as soon as
  # you join another network, and was 127.0.0.1 on any Mac not using en0.
  run run_install
  [ "$status" -eq 0 ]
  san="$(openssl x509 -in "$CERT_FILE" -noout -ext subjectAltName)"
  assert_not_contains "$san" "IP Address"
}

@test "private key is never briefly world-readable" {
  # LibreSSL, which is what Apple ships, writes the key 0644 and the
  # installer chmods it afterwards. Check it is born private instead.
  run bash -c "umask 022; HOME='$TEST_HOME' '$REPO_ROOT/install.sh' </dev/null"
  [ "$status" -eq 0 ]
  [ "$(stat -f '%Lp' "$KEY_FILE")" = "600" ]
}

@test "an old-style certificate is spotted and replaced" {
  run run_install
  [ "$status" -eq 0 ]
  # Replace it with one generated the old way: ten years, no serverAuth.
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY_FILE" -out "$CERT_FILE" -days 3650 \
    -subj "/CN=opencode.local" \
    -addext "subjectAltName=DNS:opencode.local,IP:10.0.0.1" >/dev/null 2>&1
  old="$(shasum "$CERT_FILE")"
  run bash -c "printf 'y\n' | HOME='$TEST_HOME' '$REPO_ROOT/install.sh'"
  [ "$status" -eq 0 ]
  assert_contains "$output" "certificate"
  [ "$(shasum "$CERT_FILE")" != "$old" ]
  text="$(openssl x509 -in "$CERT_FILE" -noout -text)"
  assert_contains "$text" "TLS Web Server Authentication"
}

@test "declining to replace an old certificate keeps it" {
  run run_install
  [ "$status" -eq 0 ]
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY_FILE" -out "$CERT_FILE" -days 3650 \
    -subj "/CN=opencode.local" \
    -addext "subjectAltName=DNS:opencode.local" >/dev/null 2>&1
  old="$(shasum "$CERT_FILE")"
  run bash -c "printf 'n\n' | HOME='$TEST_HOME' '$REPO_ROOT/install.sh'"
  [ "$status" -eq 0 ]
  [ "$(shasum "$CERT_FILE")" = "$old" ]
}

@test "a good certificate is left alone on re-install" {
  run run_install
  [ "$status" -eq 0 ]
  old="$(shasum "$CERT_FILE")"
  run run_install
  [ "$status" -eq 0 ]
  assert_contains "$output" "certificate already exists"
  [ "$(shasum "$CERT_FILE")" = "$old" ]
}

@test "launcher warns when the certificate is nearly expired" {
  run run_install
  [ "$status" -eq 0 ]
  stub_launcher_deps
  stub_mdns_deps
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY_FILE" -out "$CERT_FILE" -days 5 \
    -subj "/CN=opencode.local" \
    -addext "subjectAltName=DNS:opencode.local" >/dev/null 2>&1
  run "$BIN_DIR/opencode-web"
  assert_contains "$output" "expire"
}

@test "launcher refuses to start with an expired certificate" {
  run run_install
  [ "$status" -eq 0 ]
  stub_launcher_deps
  stub_mdns_deps
  # -days 1 with a start date in the past leaves it already expired.
  faketime_cert="$(mktemp -d)"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY_FILE" -out "$faketime_cert/c.pem" -days 1 \
    -not_before 20200101000000Z -not_after 20200102000000Z \
    -subj "/CN=opencode.local" \
    -addext "subjectAltName=DNS:opencode.local" >/dev/null 2>&1
  cp "$faketime_cert/c.pem" "$CERT_FILE"
  rm -rf "$faketime_cert"
  run "$BIN_DIR/opencode-web"
  [ "$status" -ne 0 ]
  assert_contains "$output" "expired"
}
