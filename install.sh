#!/bin/bash
# install.sh — one-command setup for opencode-ipad-relay.
#
# Idempotent: safe to re-run. Existing password and certificates are kept.
# Everything lives under ~/.local/bin (scripts) and ~/.local/share/opencode-web
# (cert, key, password). Nothing is installed system-wide.

set -euo pipefail

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

if [ -f "$PASSWORD_FILE" ]; then
  echo "[ok] password already set (kept)."
else
  while true; do
    printf "Choose the opencode web password (input hidden): "
    read -rs pw1
    echo ""
    if [ -z "$pw1" ]; then
      echo "password cannot be empty, try again."
      continue
    fi
    printf "Repeat it to confirm: "
    read -rs pw2
    echo ""
    if [ "$pw1" != "$pw2" ]; then
      echo "passwords do not match, try again."
      continue
    fi
    break
  done
  (umask 077 && printf '%s' "$pw1" >"$PASSWORD_FILE")
  unset pw1 pw2
  echo "[ok] password saved to $PASSWORD_FILE (mode 600)."
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
echo "  iPad:  https://opencode.local  (username 'opencode' + your password)"
echo ""
