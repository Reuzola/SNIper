"""Tests for what sniper.proxy.handle_client answers by itself: the safe-mode
PAC script, 404 for any other request made to SNIper, and the 508 that stops
a request to SNIper's own port from looping.

All OSes: the client is one end of a socket.socketpair(), and
proxy.connect_remote is replaced by a recorder that refuses, so nothing ever
leaves the machine. handle_connect turns any exception from connect_remote
into a 502, so the recorder's call list is what shows whether a request was
proxied.
"""
from __future__ import annotations

import queue
import socket
import threading

import pytest

import sniper.proxy as proxy
from sniper.logformat import friendly_format
from sniper.pac import build_pac
from sniper.proxy import ServeConfig

PORT = 8881
PAC_PATH = "/sniper-0123456789abcdef.pac"
BODY = build_pac(PORT).encode("ascii")
SAFE = ServeConfig(PORT, PAC_PATH, BODY)
COMPAT = ServeConfig(PORT, None, b"")

HEADERS = (b"HTTP/1.1 200 OK\r\n"
           b"Content-Type: application/x-ns-proxy-autoconfig\r\n"
           b"Content-Length: %d\r\n"
           b"Cache-Control: no-store, max-age=0\r\n"
           b"Connection: close\r\n\r\n" % len(BODY))
NOT_FOUND = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
LOOP = b"HTTP/1.1 508 Loop Detected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
BAD_GATEWAY = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
LOOP_WARNING = ("WARNING", "Refused a request to SNIper's own port (loop).")


@pytest.fixture
def remote(monkeypatch):
    """Recorder for connect_remote: every call is a proxied request."""
    calls = []

    def refuse(host, port, use_doh, log_q):
        calls.append((host, port))
        raise ConnectionRefusedError("refused by the test")

    monkeypatch.setattr(proxy, "connect_remote", refuse)
    return calls


def exchange(request, serve):
    """Send request as a client would, let handle_client answer it, and return
    (everything the client received until EOF, the log lines)."""
    a, b = socket.socketpair()
    log_q = queue.Queue()
    try:
        b.sendall(request)
        proxy.handle_client(a, False, 2, log_q, serve=serve)
        b.settimeout(5)
        data = b""
        while True:
            chunk = b.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        a.close()
        b.close()
    lines = []
    while not log_q.empty():
        lines.append(log_q.get_nowait())
    return data, lines


def get(path, method="GET", host="127.0.0.1:%d" % PORT):
    return ("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: test\r\n\r\n"
            % (method, path, host)).encode("ascii")


# ── The PAC script ───────────────────────────────────────────────────────────
def test_pac_get(remote):
    data, lines = exchange(get(PAC_PATH), SAFE)
    assert data == HEADERS + BODY
    assert remote == []
    # Only DEBUG, which the friendly log hides: a script fetch is no connection.
    assert [lvl for lvl, _ in lines] == ["DEBUG"]
    assert all(friendly_format(*line) is None for line in lines)


def test_pac_head_has_headers_but_no_body(remote):
    data, _ = exchange(get(PAC_PATH, "HEAD"), SAFE)
    assert data == HEADERS
    assert remote == []


@pytest.mark.parametrize("suffix", ["?x=1", "?", "?a=1&b=2"])
def test_pac_query_string_is_ignored(remote, suffix):
    data, _ = exchange(get(PAC_PATH + suffix), SAFE)
    assert data == HEADERS + BODY


def test_pac_request_split_across_packets(remote):
    # The request line and headers may arrive in pieces.
    a, b = socket.socketpair()
    try:
        request = get(PAC_PATH)
        b.sendall(request[:5])
        log_q = queue.Queue()
        t = threading.Thread(target=proxy.handle_client, args=(a, False, 2, log_q),
                             kwargs={"serve": SAFE}, daemon=True)
        t.start()
        b.sendall(request[5:])
        b.settimeout(5)
        data = b""
        while True:
            chunk = b.recv(65536)
            if not chunk:
                break
            data += chunk
        t.join(5)
    finally:
        a.close()
        b.close()
    assert data == HEADERS + BODY


# ── Anything else addressed to SNIper: 404, never proxied ───────────────────
@pytest.mark.parametrize("request_bytes, serve", [
    (get("/sniper-ffffffffffffffff.pac"), SAFE),        # another session's path
    (get("/"), SAFE),
    (get(PAC_PATH + "x"), SAFE),
    (get(PAC_PATH.upper()), SAFE),
    (get(PAC_PATH, "POST"), SAFE),
    (get(PAC_PATH, "PUT"), SAFE),
    (get(PAC_PATH, "get"), SAFE),                       # methods are case-sensitive
    (get(PAC_PATH), COMPAT),                            # nothing is served in compat mode
    (get("/"), COMPAT),
    (get(PAC_PATH), None),                              # no config at all
], ids=["other-session", "root", "longer", "case", "post", "put", "lowercase",
        "compat", "compat-root", "no-config"])
def test_other_origin_form_requests_get_404(remote, request_bytes, serve):
    data, lines = exchange(request_bytes, serve)
    assert data == NOT_FOUND
    assert remote == []
    assert [lvl for lvl, _ in lines] == ["DEBUG"]
    assert all(friendly_format(*line) is None for line in lines)


def test_origin_form_with_a_body_still_gets_404(remote):
    request = (b"POST /x HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\n\r\nabcd")
    data, _ = exchange(request, SAFE)
    assert data == NOT_FOUND
    assert remote == []


# ── Self-loop guard ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("request_line", [
    "CONNECT 127.0.0.1:%d HTTP/1.1" % PORT,
    "CONNECT localhost:%d HTTP/1.1" % PORT,
    "CONNECT LocalHost:%d HTTP/1.1" % PORT,
    "CONNECT [::1]:%d HTTP/1.1" % PORT,
    "GET http://localhost:%d/ HTTP/1.1" % PORT,
    "GET http://127.0.0.1:%d/sniper-0123456789abcdef.pac HTTP/1.1" % PORT,
    "POST http://[::1]:%d/x HTTP/1.1" % PORT,
])
def test_request_to_own_port_is_refused(remote, request_line):
    data, lines = exchange((request_line + "\r\nHost: x\r\n\r\n").encode("ascii"), SAFE)
    assert data == LOOP
    assert remote == []
    assert lines == [LOOP_WARNING]
    # Shown as written in the friendly log.
    assert friendly_format(*LOOP_WARNING) == LOOP_WARNING


def test_compat_mode_refuses_loops_too(remote):
    data, _ = exchange(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\n\r\n" % PORT, COMPAT)
    assert data == LOOP
    assert remote == []


@pytest.mark.parametrize("request_line, target", [
    ("CONNECT 127.0.0.1:%d HTTP/1.1" % (PORT + 1), ("127.0.0.1", PORT + 1)),
    ("CONNECT localhost:443 HTTP/1.1", ("localhost", 443)),
    ("CONNECT 127.0.0.2:%d HTTP/1.1" % PORT, ("127.0.0.2", PORT)),
    ("CONNECT example.com:%d HTTP/1.1" % PORT, ("example.com", PORT)),
])
def test_other_targets_are_proxied_as_before(remote, request_line, target):
    data, lines = exchange((request_line + "\r\n\r\n").encode("ascii"), SAFE)
    assert remote == [target]
    assert data == BAD_GATEWAY  # the recorder refused the connection
    assert ("INFO", "CONNECT  %s:%d" % target) in lines


def test_absolute_form_http_to_another_port_is_proxied(remote):
    data, lines = exchange(b"GET http://localhost/x HTTP/1.1\r\nHost: localhost\r\n\r\n", SAFE)
    assert remote == [("localhost", 80)]
    assert data == BAD_GATEWAY
    assert ("INFO", "GET  http://localhost/x") in lines


def test_without_a_config_nothing_counts_as_own_port(remote):
    exchange(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\n\r\n" % PORT, None)
    assert remote == [("127.0.0.1", PORT)]


def test_bad_port_in_absolute_url_is_reported_as_before(remote):
    data, lines = exchange(b"GET http://example.com:abc/ HTTP/1.1\r\n\r\n", SAFE)
    assert remote == []
    assert data == b""
    assert ("ERROR", "Bad port in URL: http://example.com:abc/") in lines


def test_serve_config_fields():
    assert ServeConfig._fields == ("listen_port", "pac_path", "pac_body")
