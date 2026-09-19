"""Integration tests for the TLS TCP relay.

These tests do NOT require opencode. They stand up a mock HTTP backend and a
real TLS relay (via ``create_server`` with an ephemeral port and a temporary
self-signed certificate generated with openssl), then exercise the relay over
real TLS connections.
"""

from __future__ import annotations

import http.server
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

# The relay module's filename contains a hyphen, so import it by path.
import importlib.util

_RELAY_PATH = Path(__file__).resolve().parents[2] / "src" / "opencode-web-proxy.py"
_spec = importlib.util.spec_from_file_location("opencode_web_relay", _RELAY_PATH)
assert _spec and _spec.loader
relay = importlib.util.module_from_spec(_spec)
# Register before executing: dataclasses looks the module up by name while
# building the class, and blows up if it isn't there yet.
sys.modules[_spec.name] = relay
_spec.loader.exec_module(relay)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def _run(cmd: list[str]) -> None:
    subprocess.run(
        cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


@pytest.fixture(scope="session")
def cert(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, str]:
    """Generate a throwaway self-signed cert/key for the relay to serve."""
    d = tmp_path_factory.mktemp("cert")
    cert = d / "cert.pem"
    key = d / "key.pem"
    _run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=opencode.local",
            "-addext",
            "subjectAltName=DNS:opencode.local,IP:127.0.0.1",
        ]
    )
    return str(cert), str(key)


class _BackendHandler(http.server.BaseHTTPRequestHandler):
    """Minimal backend: `/` returns a body; `/event` streams SSE chunks."""

    def log_message(self, *args: object) -> None:  # silence
        pass

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        if self.path == "/event":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            for i in range(3):
                try:
                    self.wfile.write(f'data: {{"seq": {i}}}\n\n'.encode())
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
                time.sleep(0.05)
            return
        body = b"<html>hello</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


_CERT_FOR_POLICY: tuple[str, str] = ("", "")


@pytest.fixture(autouse=True)
def _remember_cert(cert: tuple[str, str]) -> None:
    global _CERT_FOR_POLICY
    _CERT_FOR_POLICY = cert


@pytest.fixture()
def backend() -> tuple[str, int]:
    """Start the mock HTTP backend on an ephemeral port; yield (host, port)."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _BackendHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield "127.0.0.1", server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def relay_server(
    cert: tuple[str, str],
    backend: tuple[str, int],
    monkeypatch: pytest.MonkeyPatch,
) -> int:
    """Start the TLS relay pointing at the mock backend; yield the listen port."""
    certfile, keyfile = cert
    host, port = backend
    monkeypatch.setattr(relay, "BACKEND_HOST", host)
    monkeypatch.setattr(relay, "BACKEND_PORT", port)
    server = relay.create_server(certfile, keyfile, "127.0.0.1", 0)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def _tls_connect(
    port: int, server_hostname: str = "opencode.local", timeout: float = 10
) -> ssl.SSLSocket:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    return ctx.wrap_socket(raw, server_hostname=server_hostname)


def _http_get(port: int, path: str) -> tuple[int, bytes]:
    """Minimal HTTP/1.0 GET over TLS; returns (status, body)."""
    with _tls_connect(port) as sock:
        sock.sendall(f"GET {path} HTTP/1.0\r\nHost: opencode.local\r\n\r\n".encode())
        chunks: list[bytes] = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    raw = b"".join(chunks)
    head, _, body = raw.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0]
    status = int(status_line.split(b" ", 2)[1])
    return status, body


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


def test_tls_serves_the_opencode_local_certificate(
    relay_server: int, cert: tuple[str, str]
) -> None:
    """Verify the certificate the way an iPad that trusts it would.

    This used to assert isinstance({}, dict), which is true whatever the
    relay serves, because getpeercert() returns {} when verification is off.
    """
    certfile, _ = cert
    ctx = ssl.create_default_context(cafile=certfile)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    raw = socket.create_connection(("127.0.0.1", relay_server), timeout=10)
    with ctx.wrap_socket(raw, server_hostname="opencode.local") as sock:
        peer = sock.getpeercert()
        assert peer, "verified connection should expose the certificate"
        names = {
            value for kind, value in peer.get("subjectAltName", ()) if kind == "DNS"
        }
        assert "opencode.local" in names, peer


def test_a_certificate_for_another_name_is_rejected(
    relay_server: int, cert: tuple[str, str]
) -> None:
    """Proves the check above is doing something."""
    certfile, _ = cert
    ctx = ssl.create_default_context(cafile=certfile)
    raw = socket.create_connection(("127.0.0.1", relay_server), timeout=10)
    with pytest.raises(ssl.CertificateError):
        ctx.wrap_socket(raw, server_hostname="not-opencode.local")
    raw.close()


def test_get_root_passthrough(relay_server: int) -> None:
    status, body = _http_get(relay_server, "/")
    assert status == 200
    assert body == b"<html>hello</html>"


def test_event_stream_is_streamed_not_buffered(relay_server: int) -> None:
    """Regression test for the dead-UI bug: SSE must stream, not buffer-then-close."""
    with _tls_connect(relay_server) as sock:
        sock.sendall(b"GET /event HTTP/1.0\r\nHost: opencode.local\r\n\r\n")
        sock.settimeout(5)
        buf = b""
        first_chunk_at: float | None = None
        start = time.monotonic()
        while time.monotonic() - start < 2:
            data = sock.recv(65536)
            if not data:
                break
            buf += data
            if first_chunk_at is None and b"data:" in buf:
                first_chunk_at = time.monotonic()
        assert b"data:" in buf, "no SSE payload received through relay"
        assert b'"seq": 0' in buf and b'"seq": 1' in buf, "expected multiple events"
        # First payload should arrive well before the end (i.e. it streamed).
        assert first_chunk_at is not None
        assert first_chunk_at - start < 1.0


def test_concurrent_connections(relay_server: int) -> None:
    results: list[tuple[int, bytes]] = []
    errors: list[Exception] = []

    def worker() -> None:
        try:
            results.append(_http_get(relay_server, "/"))
        except Exception as exc:  # noqa: BLE001 - capture for assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    assert not errors, f"errors during concurrent GETs: {errors}"
    assert len(results) == 8
    assert all(
        status == 200 and body == b"<html>hello</html>" for status, body in results
    )


def _obsolete_tls_client() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_1
    ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    return ctx


def test_the_obsolete_client_can_actually_speak_tls_1_1(
    cert: tuple[str, str],
) -> None:
    """Check the test below is a real test.

    The old version of it built a TLS 1.1-only client and expected an
    SSLError. It got one -- from the client's own library, before a single
    byte was sent. It passed no matter what the relay allowed. So first
    prove this client can complete a 1.1 handshake against a server that
    permits one.
    """
    certfile, keyfile = cert
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_1
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.load_cert_chain(certfile, keyfile)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    negotiated: list[str | None] = []

    def serve() -> None:
        conn, _ = listener.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                negotiated.append(tls.version())
        except OSError:
            negotiated.append(None)

    threading.Thread(target=serve, daemon=True).start()
    raw = socket.create_connection(listener.getsockname(), timeout=10)
    try:
        with _obsolete_tls_client().wrap_socket(raw, server_hostname="x") as sock:
            assert sock.version() == "TLSv1.1"
    finally:
        listener.close()
    time.sleep(0.2)
    assert negotiated == ["TLSv1.1"]


def test_tls_1_1_is_rejected(relay_server: int) -> None:
    """A client stuck on TLS 1.1 must not get in."""
    raw = socket.create_connection(("127.0.0.1", relay_server), timeout=10)
    with pytest.raises(ssl.SSLError):
        _obsolete_tls_client().wrap_socket(raw, server_hostname="opencode.local")
    raw.close()


def test_the_protocol_floor_is_set(relay_server: int) -> None:
    context = relay.build_context(*_CERT_FOR_POLICY)
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_backend_down_closes_cleanly(
    cert: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    certfile, keyfile = cert
    # Point the relay at a port with nothing listening.
    monkeypatch.setattr(relay, "BACKEND_HOST", "127.0.0.1")
    monkeypatch.setattr(relay, "BACKEND_PORT", 1)
    server = relay.create_server(certfile, keyfile, "127.0.0.1", 0)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        port = server.server_address[1]
        with _tls_connect(port) as sock:
            sock.settimeout(5)
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
            # The relay must hang up promptly, not leave the page hanging.
            started = time.monotonic()
            try:
                assert sock.recv(1024) == b""
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
                pass
            assert time.monotonic() - started < 2
    finally:
        server.shutdown()
        server.server_close()


def test_missing_cert_exits_clearly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing_cert = tmp_path / "nope-cert.pem"
    missing_key = tmp_path / "nope-key.pem"
    monkeypatch.setattr(relay, "CERT", str(missing_cert))
    monkeypatch.setattr(relay, "KEY", str(missing_key))
    with pytest.raises(SystemExit) as excinfo:
        relay.main()
    # sys.exit(str) stores the message in SystemExit.code.
    assert "cert/key not found" in str(excinfo.value.code)


# --------------------------------------------------------------------------- #
# Availability under attack
# --------------------------------------------------------------------------- #


def test_stalled_client_does_not_block_others(
    cert: tuple[str, str], backend: tuple[str, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """One client that connects and says nothing must not freeze the relay.

    The TLS handshake used to happen inside accept(), on the single thread
    running serve_forever, so a peer that opened a socket and never sent a
    ClientHello held up every other connection until it went away.
    """
    certfile, keyfile = cert
    host, port = backend
    monkeypatch.setattr(relay, "BACKEND_HOST", host)
    monkeypatch.setattr(relay, "BACKEND_PORT", port)
    server = relay.create_server(certfile, keyfile, "127.0.0.1", 0, handshake_timeout=2)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        listen_port = server.server_address[1]
        assert _http_get(listen_port, "/") == (200, b"<html>hello</html>")

        stalled = socket.create_connection(("127.0.0.1", listen_port))
        try:
            time.sleep(0.3)
            started = time.monotonic()
            status, body = _http_get(listen_port, "/")
            assert status == 200 and body == b"<html>hello</html>"
            assert time.monotonic() - started < 3
        finally:
            stalled.close()
    finally:
        server.shutdown()
        server.server_close()


def test_silent_client_is_dropped_after_the_handshake_timeout(
    cert: tuple[str, str], backend: tuple[str, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A peer that never starts TLS is disconnected rather than held open."""
    certfile, keyfile = cert
    host, port = backend
    monkeypatch.setattr(relay, "BACKEND_HOST", host)
    monkeypatch.setattr(relay, "BACKEND_PORT", port)
    server = relay.create_server(certfile, keyfile, "127.0.0.1", 0, handshake_timeout=1)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        stalled = socket.create_connection(("127.0.0.1", server.server_address[1]))
        stalled.settimeout(6)
        assert stalled.recv(1) == b"", "server should have closed the silent client"
    finally:
        stalled.close()
        server.shutdown()
        server.server_close()


def test_backend_half_close_does_not_leak_ciphertext(
    cert: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whatever reaches the backend must be plaintext, never TLS records.

    Calling shutdown() on an SSLSocket throws away its TLS state, so the
    relay's next read on that socket returned raw encrypted bytes, which it
    then forwarded to the backend as if they were a request.
    """
    certfile, keyfile = cert
    seen: list[bytes] = []

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def serve() -> None:
        conn, _ = listener.accept()
        seen.append(conn.recv(4096))
        conn.shutdown(socket.SHUT_WR)  # done replying, still reading
        conn.settimeout(3)
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                seen.append(chunk)
        except OSError:
            pass
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    monkeypatch.setattr(relay, "BACKEND_HOST", "127.0.0.1")
    monkeypatch.setattr(relay, "BACKEND_PORT", listener.getsockname()[1])
    server = relay.create_server(certfile, keyfile, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        sock = _tls_connect(server.server_address[1])
        sock.sendall(b"FIRST")
        time.sleep(0.5)
        for _ in range(3):
            try:
                sock.sendall(b"AFTER")
            except OSError:
                break
            time.sleep(0.2)
        time.sleep(0.5)
        sock.close()
    finally:
        listener.close()
        server.shutdown()
        server.server_close()

    for chunk in seen:
        assert not chunk.startswith(b"\x17\x03"), (
            f"TLS record reached backend: {chunk!r}"
        )
        assert chunk in (b"FIRST", b"AFTER"), f"unexpected bytes at backend: {chunk!r}"


def test_idle_connection_is_closed(
    cert: tuple[str, str], backend: tuple[str, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A connection that goes quiet is eventually reclaimed."""
    certfile, keyfile = cert
    host, port = backend
    monkeypatch.setattr(relay, "BACKEND_HOST", host)
    monkeypatch.setattr(relay, "BACKEND_PORT", port)
    server = relay.create_server(certfile, keyfile, "127.0.0.1", 0, idle_timeout=1)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        sock = _tls_connect(server.server_address[1])
        sock.settimeout(6)
        assert sock.recv(1) == b"", "idle connection should have been closed"
    finally:
        sock.close()
        server.shutdown()
        server.server_close()


# --------------------------------------------------------------------------- #
# Connection limits
# --------------------------------------------------------------------------- #


def _expect_refused(port: int) -> None:
    """A connection the relay turned away, before any TLS was spoken."""
    with pytest.raises(OSError):
        sock = _tls_connect(port, timeout=5)
        sock.close()


@pytest.fixture()
def limited(
    cert: tuple[str, str], backend: tuple[str, int], monkeypatch: pytest.MonkeyPatch
):
    """Build a relay with whatever limits a test asks for."""
    certfile, keyfile = cert
    host, port = backend
    monkeypatch.setattr(relay, "BACKEND_HOST", host)
    monkeypatch.setattr(relay, "BACKEND_PORT", port)
    servers: list[relay.ThreadingTLSServer] = []

    def build(**kwargs: int) -> int:
        server = relay.create_server(
            certfile, keyfile, "127.0.0.1", 0, limits=relay.Limits(**kwargs)
        )
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server.server_address[1]

    try:
        yield build
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


def test_total_connections_are_capped(limited) -> None:
    port = limited(max_connections=2, max_per_ip=99, new_per_minute=99)
    held = [_tls_connect(port), _tls_connect(port)]
    try:
        _expect_refused(port)
    finally:
        for sock in held:
            sock.close()


def test_connections_per_address_are_capped(limited) -> None:
    port = limited(max_connections=99, max_per_ip=2, new_per_minute=99)
    held = [_tls_connect(port), _tls_connect(port)]
    try:
        _expect_refused(port)
    finally:
        for sock in held:
            sock.close()


def test_new_connections_are_rate_limited(limited) -> None:
    """Closing and reopening must not be a way around the cap."""
    port = limited(max_connections=99, max_per_ip=99, new_per_minute=3)
    for _ in range(3):
        _tls_connect(port).close()
    _expect_refused(port)


def test_a_freed_slot_can_be_reused(limited) -> None:
    """The cap counts live connections, not connections ever made."""
    port = limited(max_connections=1, max_per_ip=99, new_per_minute=99)
    first = _tls_connect(port)
    _expect_refused(port)
    first.close()
    for _ in range(40):
        try:
            _tls_connect(port).close()
            return
        except OSError:
            time.sleep(0.05)
    pytest.fail("slot was never released")


# --------------------------------------------------------------------------- #
# Brute-force resistance
# --------------------------------------------------------------------------- #


@pytest.fixture()
def always_replies():
    """A backend that answers every request with one fixed response."""
    listeners: list[socket.socket] = []

    def build(response: bytes, keep_open: bool = False) -> int:
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        listeners.append(listener)

        def serve() -> None:
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return

                def talk(conn: socket.socket = conn) -> None:
                    try:
                        while conn.recv(4096):
                            conn.sendall(response)
                            if not keep_open:
                                break
                    except OSError:
                        pass
                    conn.close()

                threading.Thread(target=talk, daemon=True).start()

        threading.Thread(target=serve, daemon=True).start()
        return listener.getsockname()[1]

    try:
        yield build
    finally:
        for listener in listeners:
            listener.close()


UNAUTHORIZED = (
    b"HTTP/1.1 401 Unauthorized\r\n"
    b'WWW-Authenticate: Basic realm="Secure Area"\r\n'
    b"Content-Length: 0\r\n\r\n"
)
OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


@pytest.fixture()
def relay_to(monkeypatch: pytest.MonkeyPatch, cert: tuple[str, str]):
    """Point a relay at an arbitrary backend port, with chosen limits."""
    certfile, keyfile = cert
    servers: list[relay.ThreadingTLSServer] = []

    def build(backend_port: int, **kwargs: float) -> int:
        monkeypatch.setattr(relay, "BACKEND_HOST", "127.0.0.1")
        monkeypatch.setattr(relay, "BACKEND_PORT", backend_port)
        server = relay.create_server(
            certfile, keyfile, "127.0.0.1", 0, limits=relay.Limits(**kwargs)
        )
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server.server_address[1]

    try:
        yield build
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


def _attempt(port: int) -> bytes:
    """One login attempt through the relay; returns everything received."""
    sock = _tls_connect(port, timeout=5)
    sock.settimeout(5)
    try:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: opencode.local\r\n\r\n")
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)
    finally:
        sock.close()


def test_a_rejected_login_ends_the_connection(always_replies, relay_to) -> None:
    """Every guess should cost a fresh TLS handshake.

    The backend here keeps the connection open, so if the relay did nothing
    an attacker could keep guessing down the same socket for free.
    """
    port = relay_to(always_replies(UNAUTHORIZED, keep_open=True))
    received = _attempt(port)  # reads until the far end closes
    assert b"401 Unauthorized" in received, received
    assert b"WWW-Authenticate" in received, "the browser still needs the challenge"


def test_a_good_response_does_not_end_a_keepalive_connection(
    always_replies, relay_to
) -> None:
    """Closing must be specific to rejected logins, not to every response."""
    port = relay_to(always_replies(OK, keep_open=True))
    sock = _tls_connect(port, timeout=5)
    sock.settimeout(5)
    try:
        for _ in range(2):
            sock.sendall(b"GET / HTTP/1.1\r\nHost: opencode.local\r\n\r\n")
            assert b"200 OK" in sock.recv(4096)
    finally:
        sock.close()


def test_repeated_rejections_lock_the_address_out(always_replies, relay_to) -> None:
    port = relay_to(
        always_replies(UNAUTHORIZED),
        auth_failures=3,
        lockout_seconds=2,
        new_per_minute=99,
    )
    for _ in range(3):
        _attempt(port)
    _expect_refused(port)


def test_a_lockout_expires(always_replies, relay_to) -> None:
    port = relay_to(
        always_replies(UNAUTHORIZED),
        auth_failures=2,
        lockout_seconds=1,
        new_per_minute=99,
    )
    for _ in range(2):
        _attempt(port)
    _expect_refused(port)
    time.sleep(1.5)
    assert b"401" in _attempt(port), "should be allowed to try again"


def test_successful_requests_never_lock_anyone_out(always_replies, relay_to) -> None:
    """The thing that would make this feature unusable is locking out someone
    who typed the right password."""
    port = relay_to(always_replies(OK), auth_failures=2, new_per_minute=99)
    for _ in range(6):
        assert b"200 OK" in _attempt(port)


# --------------------------------------------------------------------------- #
# TLS policy
# --------------------------------------------------------------------------- #


def test_only_strong_ciphers_are_offered(relay_server: int) -> None:
    """Apple's stock python3 links an OpenSSL whose defaults include CBC and
    SHA-1 suites, so the relay has to name what it will accept."""
    context = relay.build_context(*_CERT_FOR_POLICY)
    offered = [c["name"] for c in context.get_ciphers()]
    assert offered, "no ciphers at all would mean nothing can connect"
    for name in offered:
        assert "CBC" not in name, name
        assert "RC4" not in name and "3DES" not in name and "DES-" not in name, name
        assert "CAMELLIA" not in name, name
        assert not name.endswith("-SHA"), f"SHA-1 suite offered: {name}"
    assert all(
        ("GCM" in n or "CHACHA20" in n or n.startswith("TLS_")) for n in offered
    ), offered


def test_forward_secrecy_is_required(relay_server: int) -> None:
    """No static-RSA key exchange: a stolen key must not decrypt old traffic."""
    context = relay.build_context(*_CERT_FOR_POLICY)
    for cipher in context.get_ciphers():
        name = cipher["name"]
        if name.startswith("TLS_"):
            continue  # TLS 1.3 is always ephemeral
        assert name.startswith(("ECDHE", "DHE")), f"not forward secret: {name}"


def test_old_python_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "version_info", (3, 8, 0, "final", 0))
    with pytest.raises(SystemExit) as excinfo:
        relay.require_supported_python()
    assert "3.9" in str(excinfo.value.code)


def test_current_python_is_accepted() -> None:
    relay.require_supported_python()


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #


def test_connections_are_logged_without_leaking_traffic(
    relay_server: int, caplog: pytest.LogCaptureFixture
) -> None:
    """Without a log there is no way to notice someone probing the relay.

    Payload bytes must never appear: everything through here is the
    contents of the user's editor session.
    """
    with caplog.at_level("INFO", logger="opencode-web-proxy"):
        status, _ = _http_get(relay_server, "/")
        assert status == 200
        time.sleep(0.3)
    text = caplog.text
    assert "127.0.0.1" in text, f"peer address should be logged: {text!r}"
    assert "hello" not in text, "response body leaked into the log"
    assert "GET /" not in text, "request line leaked into the log"


def test_refusals_are_logged(always_replies, relay_to, caplog) -> None:
    port = relay_to(always_replies(OK), max_connections=1, new_per_minute=99)
    held = _tls_connect(port)
    try:
        with caplog.at_level("INFO", logger="opencode-web-proxy"):
            _expect_refused(port)
        assert "refus" in caplog.text.lower(), caplog.text
    finally:
        held.close()
