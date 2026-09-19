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
# Long enough for a slow phone on bad Wi-Fi, short enough that a peer
# holding a socket open without speaking TLS is not free.
HANDSHAKE_TIMEOUT = 10.0


class RelayHandler(socketserver.BaseRequestHandler):
    """Relay one accepted TLS connection to the backend, bidirectionally."""

    server: ThreadingTLSServer

    def handle(self) -> None:
        client = self._accept_tls()
        if client is None:
            return
        try:
            self._relay(client)
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _accept_tls(self) -> ssl.SSLSocket | None:
        """Complete the TLS handshake for this connection, or give up.

        The handshake deliberately happens here, on the connection's own
        thread, and under a timeout: doing it on the listening socket meant
        one peer that connected and never sent a ClientHello stalled every
        other client until it went away.
        """
        raw: socket.socket = self.request
        raw.settimeout(self.server.handshake_timeout)
        try:
            client = self.server.context.wrap_socket(
                raw, server_side=True, do_handshake_on_connect=False
            )
        except OSError:
            return None
        try:
            client.do_handshake()
        except OSError:
            try:
                client.close()
            except OSError:
                pass
            return None
        return client

    def _relay(self, client: ssl.SSLSocket) -> None:
        try:
            backend = socket.create_connection((BACKEND_HOST, BACKEND_PORT), timeout=10)
        except OSError:
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
        try:
            backend.close()
        except OSError:
            pass


class ThreadingTLSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    # The default of 5 is small for a listener that is the only way in.
    request_queue_size = 128

    context: ssl.SSLContext
    handshake_timeout: float


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
    *,
    handshake_timeout: float = HANDSHAKE_TIMEOUT,
) -> ThreadingTLSServer:
    """Build a TLS-wrapped relay server (without serving).

    The listening socket is plain TCP; TLS is negotiated per connection by
    the handler. The bound port is available via
    ``server.server_address[1]``, which lets callers pass ``listen_port=0`` for
    an ephemeral port (used by the test suite).
    """
    server = ThreadingTLSServer((listen_host, listen_port), RelayHandler)
    server.context = build_context(certfile, keyfile)
    server.handshake_timeout = handshake_timeout
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
