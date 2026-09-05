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
  [[ "$subject" == *"opencode.local"* ]]
  san="$(openssl x509 -in "$CERT_FILE" -noout -ext subjectAltName)"
  [[ "$san" == *"opencode.local"* ]]
}

@test "installer is idempotent: re-run keeps files, no re-prompt" {
  run run_install "secret-pw" "secret-pw"
  [ "$status" -eq 0 ]
  cert_before="$(shasum "$CERT_FILE")"
  pw_before="$(shasum "$PASSWORD_FILE")"

  # Second run with different piped input must NOT change anything.
  run run_install "different" "different"
  [ "$status" -eq 0 ]
  [[ "$output" == *"password already set (kept)"* ]]
  [[ "$output" == *"certificate already exists (kept)"* ]]
  [ "$(shasum "$CERT_FILE")" = "$cert_before" ]
  [ "$(shasum "$PASSWORD_FILE")" = "$pw_before" ]
}

@test "mismatched passwords are rejected and re-prompted" {
  run run_install "one" "two" "three" "three"
  [ "$status" -eq 0 ]
  [[ "$output" == *"passwords do not match"* ]]
  [ "$(cat "$PASSWORD_FILE")" = "three" ]
}

@test "empty password is rejected" {
  run run_install "" "valid" "valid"
  [ "$status" -eq 0 ]
  [[ "$output" == *"password cannot be empty"* ]]
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
  [[ "$output" == *"password file not found"* || "$output" == *"run install.sh first"* ]]
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
