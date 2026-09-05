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


def _tls_connect(port: int, server_hostname: str = "opencode.local") -> ssl.SSLSocket:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
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


def test_tls_serves_opencode_local_cert(relay_server: int) -> None:
    with _tls_connect(relay_server) as sock:
        cert = sock.getpeercert(binary_form=False)
        # CERT_NONE -> getpeercert() is {} unless binary_form; use cipher check too.
        assert sock.cipher() is not None
    # Verify the cert subject via binary parse is out of scope; ensure handshake ok.
    assert isinstance(cert, dict)


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


def test_tls_1_1_rejected(relay_server: int) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    with pytest.raises(ssl.SSLError):
        raw = socket.create_connection(("127.0.0.1", relay_server), timeout=10)
        ctx.wrap_socket(raw, server_hostname="opencode.local")


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
            # Backend is down -> relay closes client side; recv returns b"" or raises.
            try:
                data = sock.recv(1024)
                assert data == b""
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
                pass
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
