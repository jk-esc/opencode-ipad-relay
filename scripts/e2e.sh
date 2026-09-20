#!/bin/bash
# e2e.sh — drive the relay against a real opencode backend.
#
# The bats and pytest suites stub opencode out so they can run anywhere,
# which means nothing otherwise checks the two of them actually work
# together. This does: real backend, real TLS, real login, real event
# stream. It needs opencode installed, so it is not part of CI.
#
# Everything is loopback-only, on ports nobody else is using, and is torn
# down on the way out. It never touches ~/.local/share/opencode-web.
#
# No `set -e`: several checks expect a non-zero exit and report it.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

if ! command -v opencode >/dev/null 2>&1; then
  echo "opencode is not installed — skipping (this test needs the real thing)."
  exit 0
fi

WORK="$(mktemp -d)"
PASSWORD="e2e-$(date +%s)-not-a-real-password"
PIDS=()
FAILURES=0

# Only ever run by the EXIT trap, which shellcheck can't see.
# shellcheck disable=SC2317,SC2329
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  sleep 1
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
ok() { echo "    ok: $*"; }
bad() {
  echo "    FAILED: $*" >&2
  FAILURES=$((FAILURES + 1))
}

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

BACKEND_PORT="$(free_port)"
PROXY_PORT="$(free_port)"

step "generating a throwaway certificate"
(
  umask 077
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 1 \
    -subj "/CN=opencode.local" \
    -addext "subjectAltName=DNS:opencode.local,IP:127.0.0.1" \
    -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
) || {
  bad "could not generate a certificate"
  exit 1
}
ok "done"

step "starting opencode on 127.0.0.1:$BACKEND_PORT"
OPENCODE_SERVER_PASSWORD="$PASSWORD" \
  opencode serve --hostname 127.0.0.1 --port "$BACKEND_PORT" >"$WORK/backend.log" 2>&1 &
PIDS+=($!)
disown 2>/dev/null || true
for _ in $(seq 1 60); do
  lsof -nP -iTCP:"$BACKEND_PORT" -sTCP:LISTEN >/dev/null 2>&1 && break
  sleep 0.5
done
if ! lsof -nP -iTCP:"$BACKEND_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  bad "opencode never started listening"
  tail -20 "$WORK/backend.log" >&2
  exit 1
fi
ok "listening"

step "starting the relay in front of it"
python3 - "$WORK/cert.pem" "$WORK/key.pem" "$PROXY_PORT" "$BACKEND_PORT" \
  >"$WORK/relay.log" 2>&1 <<'PY' &
import importlib.util, logging, sys
spec = importlib.util.spec_from_file_location("relay", "src/opencode-web-proxy.py")
relay = importlib.util.module_from_spec(spec)
sys.modules["relay"] = relay
spec.loader.exec_module(relay)
relay.BACKEND_HOST, relay.BACKEND_PORT = "127.0.0.1", int(sys.argv[4])
logging.basicConfig(level=logging.INFO, format="%(message)s")
relay.create_server(sys.argv[1], sys.argv[2], "127.0.0.1", int(sys.argv[3])).serve_forever()
PY
PIDS+=($!)
disown 2>/dev/null || true
for _ in $(seq 1 40); do
  lsof -nP -iTCP:"$PROXY_PORT" -sTCP:LISTEN >/dev/null 2>&1 && break
  sleep 0.25
done
lsof -nP -iTCP:"$PROXY_PORT" -sTCP:LISTEN >/dev/null 2>&1 || {
  bad "the relay never started"
  cat "$WORK/relay.log" >&2
  exit 1
}
ok "listening"

step "a request with no password is challenged"
code="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$PROXY_PORT/")"
challenge="$(curl -skI "https://127.0.0.1:$PROXY_PORT/" | grep -ci 'www-authenticate')"
if [ "$code" = "401" ] && [ "$challenge" -ge 1 ]; then
  ok "401 with a WWW-Authenticate header"
else
  bad "expected a challenged 401, got $code (challenge=$challenge)"
fi

step "the right password gets through, over TLS"
code="$(curl -sk -u "opencode:$PASSWORD" -o "$WORK/config" -w '%{http_code}' \
  "https://127.0.0.1:$PROXY_PORT/config")"
if [ "$code" = "200" ] && [ -s "$WORK/config" ]; then
  ok "200, $(wc -c <"$WORK/config" | tr -d ' ') bytes"
else
  bad "expected 200 with a body, got $code"
fi

step "what TLS was actually negotiated"
tls="$(curl -skv -u "opencode:$PASSWORD" "https://127.0.0.1:$PROXY_PORT/config" 2>&1 |
  grep -i 'SSL connection using' | head -1 | sed 's/^\* *//')"
case "$tls" in
*TLSv1.3* | *TLSv1.2*) ok "$tls" ;;
*) bad "unexpected or missing TLS version: ${tls:-none}" ;;
esac

step "the event stream flows through (this is what an HTTP proxy breaks)"
curl -sk -N -u "opencode:$PASSWORD" --max-time 8 \
  "https://127.0.0.1:$PROXY_PORT/event" >"$WORK/sse" 2>/dev/null
if grep -q '^data:' "$WORK/sse"; then
  ok "$(head -c 60 "$WORK/sse" | tr -d '\n')..."
else
  bad "no events came through"
fi

step "a wrong password ends the connection"
if python3 - "$PROXY_PORT" <<'PY'
import base64, socket, ssl, sys
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = ctx.wrap_socket(
    socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10),
    server_hostname="opencode.local",
)
sock.settimeout(10)
cred = base64.b64encode(b"opencode:wrong").decode()
sock.sendall(
    f"GET / HTTP/1.1\r\nHost: opencode.local\r\n"
    f"Authorization: Basic {cred}\r\n\r\n".encode()
)
seen = b""
while True:
    try:
        chunk = sock.recv(4096)
    except (OSError, ssl.SSLError):
        break
    if not chunk:
        break
    seen += chunk
sock.close()
sys.exit(0 if b"401" in seen else 1)
PY
then
  ok "401 delivered, then the relay hung up"
else
  bad "the connection was not closed after a rejected login"
fi

step "the log records connections but never traffic"
connections="$(grep -cE 'connected|closed' "$WORK/relay.log")"
if [ "$connections" -gt 0 ]; then
  ok "$connections connection lines"
else
  bad "nothing was logged"
fi
if grep -qiE "$PASSWORD|authorization|GET /" "$WORK/relay.log"; then
  bad "the log contains request data or credentials"
else
  ok "no credentials or request data in the log"
fi

step "only loopback is listening"
exposed="$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null |
  awk -v a=":$BACKEND_PORT" -v b=":$PROXY_PORT" \
    '$9 ~ a"$" || $9 ~ b"$" {print $9}' | grep -vc '^127\.0\.0\.1:')"
if [ "$exposed" -eq 0 ]; then
  ok "both sockets are on 127.0.0.1"
else
  bad "$exposed socket(s) reachable off this machine"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "All end-to-end checks passed."
else
  echo "$FAILURES end-to-end check(s) failed." >&2
fi
exit "$FAILURES"
