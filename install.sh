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

# Apple publishes what iOS and macOS require of a certificate they will
# trust (support.apple.com/103769): SHA-2, a DNS name in subjectAltName, an
# extendedKeyUsage of serverAuth, and 825 days or fewer. Whether iPadOS
# enforces the last two for a self-signed certificate you installed
# yourself is not something we can rely on either way, so meet them.
CERT_DAYS=825
LOCAL_NAME="$(scutil --get LocalHostName 2>/dev/null || hostname -s).local"

generate_cert() {
  # umask, not a chmod afterwards: LibreSSL, which is what Apple ships,
  # writes the key 0644 and leaves it that way until we fix it.
  (
    umask 077
    openssl req -x509 -newkey rsa:4096 -nodes \
      -keyout "$KEY_FILE" \
      -out "$CERT_FILE" \
      -days "$CERT_DAYS" \
      -subj "/CN=opencode.local" \
      -addext "subjectAltName=DNS:opencode.local,DNS:$LOCAL_NAME" \
      -addext "extendedKeyUsage=serverAuth" \
      -addext "keyUsage=digitalSignature,keyEncipherment" \
      -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
  )
  chmod 600 "$KEY_FILE"
  chmod 644 "$CERT_FILE"
  echo "[ok] generated a certificate for opencode.local and $LOCAL_NAME,"
  echo "     good for $CERT_DAYS days."
}

is_yes() {
  case "$1" in
  y | Y | yes | YES) return 0 ;;
  esac
  return 1
}

# Why an existing certificate would need replacing, or empty if it's fine.
cert_complaint() {
  local text
  text="$(openssl x509 -in "$CERT_FILE" -noout -text 2>/dev/null)" || {
    echo "it cannot be read"
    return
  }
  case "$text" in
  *"TLS Web Server Authentication"*) ;;
  *)
    echo "it has no serverAuth purpose, which Apple requires"
    return
    ;;
  esac
  # 825 days from now: anything still valid then is longer-lived than allowed.
  if openssl x509 -in "$CERT_FILE" -noout -checkend 71280000 >/dev/null 2>&1; then
    echo "it lasts longer than the 825 days Apple allows"
    return
  fi
  case "$text" in
  *"IP Address:"*)
    echo "it pins an IP address that will go stale"
    return
    ;;
  esac
}

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
  generate_cert
else
  complaint="$(cert_complaint)"
  if [ -z "$complaint" ]; then
    echo "[ok] certificate already exists (kept)."
  else
    echo "Your certificate needs replacing: $complaint."
    echo "You will have to install and trust the new one on your iPad."
    printf "Replace it now? [y/N] "
    if IFS= read -r reply && is_yes "$reply"; then
      generate_cert
    else
      echo "[kept] certificate left as it is."
    fi
  fi
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
