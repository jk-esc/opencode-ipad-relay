#!/bin/bash
# uninstall.sh — remove opencode-ipad-relay from this machine.

set -euo pipefail

BIN_DIR="$HOME/.local/bin"
DATA_DIR="$HOME/.local/share/opencode-web"

echo "opencode-ipad-relay uninstaller"
echo "==============================="
echo ""

# Stop anything currently running. Only PIDs the launcher recorded itself:
# matching on command lines (pkill -f) also hits editors and pagers that
# happen to have the file open.
PID_FILE="$DATA_DIR/run.pid"
if [ -f "$PID_FILE" ]; then
  while read -r pid; do
    [ -n "$pid" ] || continue
    kill "$pid" 2>/dev/null || true
  done <"$PID_FILE"
  rm -f "$PID_FILE"
  echo "[ok] stopped the running relay and backend"
fi

rm -f "$BIN_DIR/opencode-web" "$BIN_DIR/opencode-web-proxy.py"
echo "[ok] removed $BIN_DIR/opencode-web and $BIN_DIR/opencode-web-proxy.py"

if [ -d "$DATA_DIR" ]; then
  echo ""
  printf "Also delete %s (contains your certificate, private key and password)? [y/N] " "$DATA_DIR"
  read -r answer
  case "$answer" in
  y | Y | yes | YES)
    rm -rf "$DATA_DIR"
    echo "[ok] removed $DATA_DIR"
    ;;
  *)
    echo "[kept] $DATA_DIR (certificate and password preserved)"
    ;;
  esac
fi

echo ""
echo "Done. Don't forget to remove the 'opencode.local' profile on your iPad"
echo "(Settings -> General -> VPN & Device Management) if you no longer need it."
