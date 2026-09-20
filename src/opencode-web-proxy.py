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
import logging
import socketserver
import ssl
import sys
import threading
import time

CERT_DIR = os.path.expanduser("~/.local/share/opencode-web")
CERT = os.path.join(CERT_DIR, "cert.pem")
KEY = os.path.join(CERT_DIR, "key.pem")


def port_from_env(name: str, raw: str | None, default: int) -> int:
    """Read a port override, and explain it rather than throw a traceback."""
    if raw is None or raw == "":
        return default
    try:
        port = int(raw)
    except ValueError:
        sys.exit(f"{name} must be a port number, got {raw!r}")
    if not 1 <= port <= 65535:
        sys.exit(f"{name} must be between 1 and 65535, got {raw!r}")
    return port


# Overrides exist so the relay can be run somewhere harmless while testing.
LISTEN_PORT = port_from_env(
    "OPENCODE_WEB_PROXY_PORT", os.environ.get("OPENCODE_WEB_PROXY_PORT"), 443
)
BACKEND_HOST = os.environ.get("OPENCODE_WEB_BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = port_from_env(
    "OPENCODE_WEB_BACKEND_PORT", os.environ.get("OPENCODE_WEB_BACKEND_PORT"), 4096
)
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
# How often to sweep per-address history that has aged out.
PRUNE_INTERVAL = 60.0
# Only forward-secret AEAD suites. Worth naming explicitly: Apple's stock
# python3 links LibreSSL 2.8.3, whose defaults still include CBC and SHA-1
# suites. Leaves six suites there and nine (with TLS 1.3) on OpenSSL 3.
CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!SHA1"
MIN_PYTHON = (3, 9)
# Status lines that mean "wrong password". Matched on the first bytes of a
# response, which is not HTTP parsing: we never look inside, buffer, or
# reorder anything, and a response we mis-read only costs that connection.
REJECTED = (b"HTTP/1.1 401", b"HTTP/1.0 401")


LOG = logging.getLogger("opencode-web-proxy")


@dataclasses.dataclass(frozen=True)
class Limits:
    """What one relay is willing to serve at once.

    A browser opens a handful of connections per page, so these are far
    above normal use and only bite when something is hammering the relay.
    """

    max_connections: int = 64
    max_per_ip: int = 16
    new_per_minute: int = 30
    # Rejected logins tolerated from one address before it is shut out.
    # A page load can legitimately produce a few, so this is not tight.
    auth_failures: int = 20
    auth_window: float = 600.0
    lockout_seconds: float = 900.0


class RelayHandler(socketserver.BaseRequestHandler):
    """Relay one accepted TLS connection to the backend, bidirectionally."""

    server: ThreadingTLSServer

    def handle(self) -> None:
        ip = self.server.peer_ip(self.client_address)
        client = self._accept_tls()
        if client is None:
            LOG.info("no TLS handshake from %s", ip)
            return
        LOG.info("connected %s (%s)", ip, client.version())
        try:
            self._relay(client)
        finally:
            LOG.info("closed %s", ip)
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
        drop_after_flush = False
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
                        if data.startswith(REJECTED):
                            # Pass the challenge on so the browser can ask
                            # again, then hang up: every guess should cost a
                            # whole new TLS handshake.
                            drop_after_flush = True
                            if self.server.note_rejected_login(self.client_address):
                                LOG.warning(
                                    "locking out %s after repeated bad logins",
                                    self.server.peer_ip(self.client_address),
                                )
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

            if drop_after_flush and not to_client:
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
        self._failures: dict[str, collections.deque[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._next_prune = 0.0

    def _prune(self, now: float) -> None:
        """Forget addresses we have no reason to remember.

        There is one deque per address here, and without this they pile up
        for every peer that ever connects. Only entries that have aged out
        of their window go; a live or locked-out address is kept, so this
        can't be used to wipe a lockout.
        """
        self._next_prune = now + PRUNE_INTERVAL
        for ip in [ip for ip, until in self._locked_until.items() if now >= until]:
            del self._locked_until[ip]
        tables = (
            (self._recent, RATE_WINDOW),
            (self._failures, self.limits.auth_window),
        )
        for table, window in tables:
            stale = [
                ip
                for ip, seen in table.items()
                if (not seen or now - seen[-1] > window)
                and ip not in self._live_by_ip
                and ip not in self._locked_until
            ]
            for ip in stale:
                del table[ip]

    def note_rejected_login(self, client_address: tuple[str, int] | str) -> bool:
        """Count one wrong password. True if that address is now shut out."""
        ip = self.peer_ip(client_address)
        now = time.monotonic()
        with self._lock:
            failures = self._failures.setdefault(ip, collections.deque())
            while failures and now - failures[0] > self.limits.auth_window:
                failures.popleft()
            failures.append(now)
            if len(failures) < self.limits.auth_failures:
                return False
            self._locked_until[ip] = now + self.limits.lockout_seconds
            failures.clear()
            return True

    @staticmethod
    def peer_ip(client_address: tuple[str, int] | str) -> str:
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
        ip = self.peer_ip(client_address)
        now = time.monotonic()
        with self._lock:
            if now >= self._next_prune:
                self._prune(now)
            locked_until = self._locked_until.get(ip)
            if locked_until is not None:
                if now < locked_until:
                    LOG.info(
                        "refused %s: locked out for another %.0fs",
                        ip,
                        locked_until - now,
                    )
                    return False
                del self._locked_until[ip]
            recent = self._recent.setdefault(ip, collections.deque())
            while recent and now - recent[0] > RATE_WINDOW:
                recent.popleft()
            if len(recent) >= self.limits.new_per_minute:
                refusal = "connecting too often"
            elif self._live_total >= self.limits.max_connections:
                refusal = "relay is full"
            elif self._live_by_ip[ip] >= self.limits.max_per_ip:
                refusal = "too many connections from this address"
            else:
                refusal = ""
            if refusal:
                LOG.info("refused %s: %s", ip, refusal)
                return False
            recent.append(now)
            self._live_total += 1
            self._live_by_ip[ip] += 1
        return True

    def release_request(self, client_address: tuple[str, int] | str) -> None:
        """Give back the slot taken by verify_request()."""
        ip = self.peer_ip(client_address)
        with self._lock:
            self._live_total -= 1
            self._live_by_ip[ip] -= 1
            if self._live_by_ip[ip] <= 0:
                del self._live_by_ip[ip]

    def process_request(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int] | str,
    ) -> None:
        # The slot is normally given back by the connection's own thread. If
        # that thread can't be started there is no thread to do it, and the
        # seat would stay taken for the life of the process.
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.release_request(client_address)
            raise

    def process_request_thread(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int] | str,
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.release_request(client_address)


def require_supported_python() -> None:
    """Refuse to run somewhere the TLS settings below would not hold."""
    if sys.version_info < MIN_PYTHON:
        sys.exit(
            f"python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer is required "
            f"(this is {sys.version.split()[0]})"
        )


def build_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    """Create a TLS server context with a modern protocol floor."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(CIPHERS)
    context.options |= ssl.OP_NO_COMPRESSION
    context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    # Absent on LibreSSL, which is what Apple's python3 links.
    context.options |= getattr(ssl, "OP_NO_RENEGOTIATION", 0)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def create_server(
    certfile: str,
    keyfile: str,
    # Listening on every interface is the whole point: this is the LAN-facing
    # front door, and it is what keeps the backend on 127.0.0.1.
    listen_host: str = "0.0.0.0",  # nosec B104
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
    require_supported_python()
    if not (os.path.exists(CERT) and os.path.exists(KEY)):
        sys.exit(
            "cert/key not found; run install.sh first "
            "(expected in ~/.local/share/opencode-web/)"
        )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    # LAN-facing by design; see create_server().
    server = create_server(CERT, KEY, "0.0.0.0", LISTEN_PORT)  # nosec B104
    best = "TLS 1.3" if ssl.HAS_TLSv1_3 else "TLS 1.2"
    LOG.info(
        "listening on 0.0.0.0:%s -> %s:%s (%s, up to %s)",
        LISTEN_PORT,
        BACKEND_HOST,
        BACKEND_PORT,
        ssl.OPENSSL_VERSION,
        best,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
