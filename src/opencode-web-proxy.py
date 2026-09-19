#!/usr/bin/env python3
"""TLS-terminating TCP relay: HTTPS on 0.0.0.0:443 -> 127.0.0.1:4096 (opencode web).

Stdlib-only. Terminates TLS with the self-signed opencode.local certificate, then
relays raw bytes bidirectionally to the local opencode server. No HTTP parsing:
WebSockets, Server-Sent Events, keep-alive and streaming pass through untouched,
which the opencode web UI requires.
"""

from __future__ import annotations

import collections
import dataclasses
import os
import select
import socket
import socketserver
import ssl
import sys
import threading
import time

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
# A live page holds an event stream open, so this only has to be longer than
# the gap between reconnects. The browser reopens the stream by itself.
IDLE_TIMEOUT = 900.0
# Most we will hold for one direction before we stop reading the other.
MAX_BUFFER = 1024 * 1024
# How often an otherwise quiet connection re-checks its idle deadline.
POLL_INTERVAL = 1.0
RATE_WINDOW = 60.0


@dataclasses.dataclass(frozen=True)
class Limits:
    """What one relay is willing to serve at once.

    A browser opens a handful of connections per page, so these are far
    above normal use and only bite when something is hammering the relay.
    """

    max_connections: int = 64
    max_per_ip: int = 16
    new_per_minute: int = 30


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
        try:
            self._pump(client, backend)
        finally:
            try:
                backend.close()
            except OSError:
                pass

    def _pump(self, client: ssl.SSLSocket, backend: socket.socket) -> None:
        """Shuttle bytes between the TLS client and the backend.

        One thread, both directions, because an SSLSocket is not safe to read
        on one thread while writing it on another: a read can drive a write
        internally (a TLS 1.3 key update, say) and the two corrupt each
        other's state.

        The TLS side is never half-closed. SSLSocket.shutdown() discards the
        TLS state, after which reads return raw ciphertext -- which used to
        get forwarded to the backend as if it were a request.
        """
        idle_timeout = self.server.idle_timeout
        client.setblocking(False)
        backend.setblocking(False)

        to_backend = bytearray()
        to_client = bytearray()
        client_done = False  # client will send nothing more
        backend_done = False
        backend_write_closed = False
        deadline = time.monotonic() + idle_timeout

        while True:
            if time.monotonic() > deadline:
                return

            # Stop reading a side whose outbound buffer is already full, so a
            # fast peer cannot make us hold unbounded data for a slow one.
            readers: list[socket.socket] = []
            if not client_done and len(to_backend) < MAX_BUFFER:
                readers.append(client)
            if not backend_done and len(to_client) < MAX_BUFFER:
                readers.append(backend)
            writers: list[socket.socket] = []
            if to_backend:
                writers.append(backend)
            if to_client:
                writers.append(client)

            if not readers and not writers:
                return

            # Decrypted bytes can already be buffered inside the SSL object,
            # where select() cannot see them.
            ready_now = client in readers and client.pending()
            try:
                readable, writable, _ = select.select(
                    readers, writers, [], 0 if ready_now else POLL_INTERVAL
                )
            except OSError:
                return
            if ready_now and client not in readable:
                readable = [*readable, client]

            progressed = False

            for sock in readable:
                try:
                    data = sock.recv(BUFSIZE)
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
                    continue
                except OSError:
                    return
                if data:
                    progressed = True
                    if sock is client:
                        to_backend += data
                    else:
                        to_client += data
                elif sock is client:
                    client_done = True
                else:
                    backend_done = True

            for sock in writable:
                buf = to_backend if sock is backend else to_client
                if not buf:
                    continue
                try:
                    sent = sock.send(buf)
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
                    continue
                except OSError:
                    return
                if sent:
                    progressed = True
                    del buf[:sent]

            if progressed:
                deadline = time.monotonic() + idle_timeout

            # The client is finished and everything it said has been passed
            # on: tell the backend, so it stops waiting for more. This side is
            # plain TCP, so half-closing it is safe.
            if client_done and not to_backend and not backend_write_closed:
                backend_write_closed = True
                try:
                    backend.shutdown(socket.SHUT_WR)
                except OSError:
                    return

            # Once the backend is done and the client has everything, we are
            # done. Closing outright is the only clean end for the TLS side.
            if backend_done and not to_client:
                return


class ThreadingTLSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    # The default of 5 is small for a listener that is the only way in.
    request_queue_size = 128

    context: ssl.SSLContext
    handshake_timeout: float
    idle_timeout: float
    limits: Limits

    def _init_limits(self, limits: Limits) -> None:
        self.limits = limits
        self._lock = threading.Lock()
        self._live_total = 0
        self._live_by_ip: collections.Counter[str] = collections.Counter()
        self._recent: dict[str, collections.deque[float]] = {}

    @staticmethod
    def _peer_ip(client_address: tuple[str, int] | str) -> str:
        return (
            client_address[0] if isinstance(client_address, tuple) else client_address
        )

    def verify_request(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int] | str,
    ) -> bool:
        """Decide whether to serve this connection, before any TLS.

        This runs on the accept thread, so a refusal costs us a socket close
        and nothing else -- no handshake, no key exchange, no thread. The
        peer sees the connection drop.
        """
        ip = self._peer_ip(client_address)
        now = time.monotonic()
        with self._lock:
            recent = self._recent.setdefault(ip, collections.deque())
            while recent and now - recent[0] > RATE_WINDOW:
                recent.popleft()
            if len(recent) >= self.limits.new_per_minute:
                return False
            if self._live_total >= self.limits.max_connections:
                return False
            if self._live_by_ip[ip] >= self.limits.max_per_ip:
                return False
            recent.append(now)
            self._live_total += 1
            self._live_by_ip[ip] += 1
        return True

    def process_request_thread(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int] | str,
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            ip = self._peer_ip(client_address)
            with self._lock:
                self._live_total -= 1
                self._live_by_ip[ip] -= 1
                if self._live_by_ip[ip] <= 0:
                    del self._live_by_ip[ip]


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
    idle_timeout: float = IDLE_TIMEOUT,
    limits: Limits | None = None,
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
    server.idle_timeout = idle_timeout
    server._init_limits(limits or Limits())
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
