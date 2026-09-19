#!/bin/bash
# install.sh — one-command setup for opencode-ipad-relay.
#
# Idempotent: safe to re-run. Existing password and certificates are kept.
# Everything lives under ~/.local/bin (scripts) and ~/.local/share/opencode-web
# (cert, key, password). Nothing is installed system-wide.

set -euo pipefail

usage() {
  cat <<'USAGE'
usage: ./install.sh [--password] [--help]

  (no flags)   generate a strong password and show it once
  --password   choose your own password instead (prompted, hidden)
  --help       show this message
USAGE
}

CHOOSE_PASSWORD=0
while [ "$#" -gt 0 ]; do
  case "$1" in
  --password) CHOOSE_PASSWORD=1 ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "error: unknown option '$1'" >&2
    echo "" >&2
    usage >&2
    exit 2
    ;;
  esac
  shift
done

MIN_PASSWORD_LEN=12

SRC_DIR="$(cd "$(dirname "$0")/src" && pwd)"
BIN_DIR="$HOME/.local/bin"
DATA_DIR="$HOME/.local/share/opencode-web"
PASSWORD_FILE="$DATA_DIR/password"
CERT_FILE="$DATA_DIR/cert.pem"
KEY_FILE="$DATA_DIR/key.pem"

echo "opencode-ipad-relay installer"
echo "============================="
echo ""

# --- 1. Preflight ----------------------------------------------------------

if [ "$(uname -s)" != "Darwin" ]; then
  echo "error: this project only supports macOS." >&2
  exit 1
fi

missing=0
for tool in opencode python3 openssl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: '$tool' not found on PATH." >&2
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  echo "" >&2
  echo "Install the missing tools first (e.g. 'brew install opencode python openssl')." >&2
  exit 1
fi

mkdir -p "$BIN_DIR" "$DATA_DIR"
chmod 700 "$DATA_DIR"

case ":$PATH:" in
*":$BIN_DIR:"*) ;;
*)
  echo "note: $BIN_DIR is not in your PATH."
  echo "      add this to your shell profile (e.g. ~/.zshrc):"
  echo "        export PATH=\"\$HOME/.local/bin:\$PATH\""
  echo ""
  ;;
esac

# --- 2. Password -----------------------------------------------------------

# Anyone who has this password can run commands on this Mac, and neither
# opencode nor the relay can tell a guess from a typo, so a generated one
# is the default. 20 characters from a 32-symbol alphabet is 100 bits.
# The alphabet has no capitals and no 0/O/1/l, to be typeable on an iPad.
generate_password() {
  python3 -c '
import secrets
alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
pw = "".join(secrets.choice(alphabet) for _ in range(20))
print("-".join(pw[i : i + 5] for i in range(0, 20, 5)))
'
}

prompt_password() {
  local pw1 pw2
  while true; do
    printf "Choose the opencode web password (input hidden): " >&2
    if ! IFS= read -rs pw1; then
      echo "" >&2
      echo "error: no password given (stdin ended)." >&2
      return 1
    fi
    echo "" >&2
    if [ -z "$pw1" ]; then
      echo "password cannot be empty, try again." >&2
      continue
    fi
    if [ "${#pw1}" -lt "$MIN_PASSWORD_LEN" ]; then
      echo "password must be at least $MIN_PASSWORD_LEN characters, try again." >&2
      continue
    fi
    printf "Repeat it to confirm: " >&2
    if ! IFS= read -rs pw2; then
      echo "" >&2
      echo "error: no password given (stdin ended)." >&2
      return 1
    fi
    echo "" >&2
    if [ "$pw1" != "$pw2" ]; then
      echo "passwords do not match, try again." >&2
      continue
    fi
    printf '%s' "$pw1"
    return 0
  done
}

GENERATED_PASSWORD=""
if [ -f "$PASSWORD_FILE" ]; then
  echo "[ok] password already set (kept)."
elif [ "$CHOOSE_PASSWORD" -eq 1 ]; then
  pw="$(prompt_password)"
  (umask 077 && printf '%s' "$pw" >"$PASSWORD_FILE")
  unset pw
  echo "[ok] password saved to $PASSWORD_FILE (mode 600)."
else
  GENERATED_PASSWORD="$(generate_password)"
  (umask 077 && printf '%s' "$GENERATED_PASSWORD" >"$PASSWORD_FILE")
  echo "[ok] generated a password and saved it to $PASSWORD_FILE (mode 600)."
  echo "     (re-run with --password to choose your own instead)"
fi

# --- 3. Certificate --------------------------------------------------------

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
  echo "[ok] certificate already exists (kept)."
else
  LAN_IP="$(ipconfig getifaddr en0 2>/dev/null || echo 127.0.0.1)"
  openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 3650 \
    -subj "/CN=opencode.local" \
    -addext "subjectAltName=DNS:opencode.local,IP:$LAN_IP"
  chmod 600 "$KEY_FILE"
  chmod 644 "$CERT_FILE"
  echo "[ok] generated self-signed certificate (10 years, CN=opencode.local, IP SAN $LAN_IP)."
fi

# --- 4. Scripts ------------------------------------------------------------

cp "$SRC_DIR/opencode-web" "$BIN_DIR/opencode-web"
cp "$SRC_DIR/opencode-web-proxy.py" "$BIN_DIR/opencode-web-proxy.py"
chmod 700 "$BIN_DIR/opencode-web" "$BIN_DIR/opencode-web-proxy.py"
echo "[ok] installed opencode-web and opencode-web-proxy.py to $BIN_DIR."

# --- 5. Next steps ---------------------------------------------------------

echo ""
echo "Setup complete. Remaining one-time step (on the iPad):"
echo ""
echo "  1. AirDrop (or email) this file to your iPad:"
echo "       $CERT_FILE"
echo "  2. On the iPad: open it -> Install Profile (enter passcode)."
echo "  3. Settings -> General -> About -> Certificate Trust Settings ->"
echo "     enable full trust for 'opencode.local'."
echo ""
echo "Then, whenever you want to use it:"
echo ""
echo "  Mac:   opencode-web"
echo "  iPad:  https://opencode.local"
echo ""
if [ -n "$GENERATED_PASSWORD" ]; then
  echo "  Log in as 'opencode' with this password:"
  echo ""
  echo "      $GENERATED_PASSWORD"
  echo ""
  echo "  It is written down in $PASSWORD_FILE if you lose it."
else
  echo "  Log in as 'opencode' with your password."
fi
echo ""
