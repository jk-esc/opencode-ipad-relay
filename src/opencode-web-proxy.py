#!/usr/bin/env python3
"""TLS-terminating TCP relay: HTTPS on 0.0.0.0:443 -> 127.0.0.1:4096 (opencode web).

Stdlib-only. Terminates TLS with the self-signed opencode.local certificate, then
relays raw bytes bidirectionally to the local opencode server. No HTTP parsing:
WebSockets, Server-Sent Events, keep-alive and streaming pass through untouched,
which the opencode web UI requires.
"""

from __future__ import annotations

import os
import socket
import socketserver
import ssl
import sys
import threading

CERT_DIR = os.path.expanduser("~/.local/share/opencode-web")
CERT = os.path.join(CERT_DIR, "cert.pem")
KEY = os.path.join(CERT_DIR, "key.pem")
LISTEN_PORT = int(os.environ.get("OPENCODE_WEB_PROXY_PORT", "443"))
BACKEND_HOST = os.environ.get("OPENCODE_WEB_BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = int(os.environ.get("OPENCODE_WEB_BACKEND_PORT", "4096"))
BUFSIZE = 64 * 1024


class RelayHandler(socketserver.BaseRequestHandler):
    """Relay one accepted TLS connection to the backend, bidirectionally."""

    def handle(self) -> None:
        client: socket.socket = self.request
        try:
            backend = socket.create_connection((BACKEND_HOST, BACKEND_PORT), timeout=10)
        except OSError:
            client.close()
            return
        client.settimeout(None)
        backend.settimeout(None)

        def pump(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    data = src.recv(BUFSIZE)
                    if not data:
                        try:
                            dst.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        break
                    dst.sendall(data)
            except OSError:
                pass

        t1 = threading.Thread(target=pump, args=(client, backend), daemon=True)
        t2 = threading.Thread(target=pump, args=(backend, client), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        for sock in (client, backend):
            try:
                sock.close()
            except OSError:
                pass


class ThreadingTLSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def build_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    """Create a TLS server context with a modern protocol floor."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def create_server(
    certfile: str,
    keyfile: str,
    # nosec B104 - 0.0.0.0 is required: the relay is the LAN-facing TLS front
    # end by design (the opencode backend stays on 127.0.0.1).
    listen_host: str = "0.0.0.0",
    listen_port: int = 443,
) -> ThreadingTLSServer:
    """Build a TLS-wrapped relay server (without serving).

    The listening socket's bound port is available via
    ``server.server_address[1]``, which lets callers pass ``listen_port=0`` for
    an ephemeral port (used by the test suite).
    """
    context = build_context(certfile, keyfile)
    server = ThreadingTLSServer((listen_host, listen_port), RelayHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main() -> None:
    if not (os.path.exists(CERT) and os.path.exists(KEY)):
        sys.exit(
            "cert/key not found; run install.sh first "
            "(expected in ~/.local/share/opencode-web/)"
        )
    # LAN-facing by design; see create_server().
    server = create_server(CERT, KEY, "0.0.0.0", LISTEN_PORT)  # nosec B104
    print(
        f"TLS proxy listening on 0.0.0.0:{LISTEN_PORT} -> {BACKEND_HOST}:{BACKEND_PORT}"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
