"""Tests for sniper.server.ProxyServer: the accept loop's error handling and
fail-safe, the idempotent stop(), the session-end hooks, safe vs.
Compatibility mode (the PAC script it serves) and connection backpressure.

winproxy is never reached: proxy_enable / proxy_restore are replaced by a
recorder, so nothing here can touch any registry. Real sockets on 127.0.0.1
are used where the point is what a client actually experiences.
"""
from __future__ import annotations

import errno
import re
import socket
import threading
import time
import types
import urllib.error
import urllib.request

import pytest

import sniper.server as server_mod
from helpers import wait_until
from sniper.compat import IS_WINDOWS
from sniper.pac import build_pac
from sniper.server import ProxyServer, _is_transient_accept_error

ERROR_LINE = ("ERROR", "Accept error — proxy stopped unexpectedly.")
STOPPED_LINE = ("INFO", "Proxy stopped. Windows proxy restored.")
KEPT_LINE = ("INFO", "Proxy server stopped; your manual proxy change was left in place.")
RESTORED_AFTER_LINE = ("INFO", "Windows proxy restored after the unexpected stop.")
CANCELLED_LINE = ("INFO", "Sign-out was cancelled — system proxy re-applied.")
LIMIT_LINE = ("WARNING", "Connection limit (%d) reached — new connections wait for a free slot")
PAC_URL_RX = r"^http://127\.0\.0\.1:%d/sniper-[0-9a-f]{16}\.pac$"

TRANSIENT_WSA = [10004, 10024, 10035, 10053, 10054, 10055]
TRANSIENT_POSIX = ["EINTR", "EMFILE", "ENFILE", "ENOBUFS", "ECONNABORTED",
                   "ECONNRESET", "EAGAIN", "EWOULDBLOCK"]


# ── Recorders and fakes ──────────────────────────────────────────────────────
class WinproxyRecorder:
    """Stands in for proxy_enable / proxy_restore / current_session_id and
    records each call in order. "enable-done" marks when an enable returned,
    so tests can tell whether a restore landed before or after an apply
    finished. A finished enable makes its session the record's, unless
    writes_record is False (as when Group Policy locks the proxy)."""

    def __init__(self):
        self.ops = []
        self.pac_urls = []      # the pac_url of each enable, in order
        self.session_ids = []   # the session_id of each enable, in order
        self.lock = threading.Lock()
        self.restore_result = None
        self.restore_exc = None
        self.enable_exc = None
        self.enable_hook = None
        self.writes_record = True
        self.current = None     # the session the record names, or None

    def _log(self, *op):
        with self.lock:
            self.ops.append(op)

    def enable(self, addr, pac_url=None, session_id=None):
        self._log("enable", addr)
        with self.lock:
            self.pac_urls.append(pac_url)
            self.session_ids.append(session_id)
        if self.enable_hook:
            self.enable_hook(addr)
        if self.enable_exc:
            raise self.enable_exc
        if self.writes_record:
            self.current = session_id
        self._log("enable-done", addr)
        return None

    def restore(self, session_id=None):
        self._log("restore")
        if self.restore_exc:
            raise self.restore_exc
        self.current = None
        return self.restore_result

    def current_session_id(self):
        return self.current

    @property
    def enables(self):
        return [op[1] for op in self.ops if op[0] == "enable"]

    @property
    def restores(self):
        return sum(1 for op in self.ops if op[0] == "restore")


class FakeClient:
    def __init__(self):
        self.closed = False
        self.close_count = 0

    def close(self):
        self.closed = True
        self.close_count += 1


CLIENT = "client"   # script item: accept() returns a new FakeClient


class ScriptedListener:
    """A listening socket whose accept() plays back a script.

    Items: an exception to raise, CLIENT to accept a FakeClient, or a callable
    whose result is treated as an item (so it can sleep or poke the server
    first). When the script runs out, the server's stop event is set and
    accept() times out, which ends the loop exactly like a normal Stop.
    """

    def __init__(self, server, script):
        self.server = server
        self.script = iter(script)
        self.closed = 0
        self.accepts = 0
        self.clients = []

    def accept(self):
        self.accepts += 1
        if self.closed:
            raise OSError(errno.EBADF, "closed")
        item = next(self.script, None)
        if item is None:
            self.server._stop.set()
            raise socket.timeout("timed out")
        if callable(item):
            item = item()
        if isinstance(item, BaseException):
            raise item
        assert item == CLIENT
        client = FakeClient()
        self.clients.append(client)
        return client, ("127.0.0.1", 50000)

    def close(self):
        self.closed += 1


def _raise(exc):
    raise exc


def drain(q):
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


@pytest.fixture
def wp(monkeypatch):
    rec = WinproxyRecorder()
    monkeypatch.setattr(server_mod, "proxy_enable", rec.enable)
    monkeypatch.setattr(server_mod, "proxy_restore", rec.restore)
    monkeypatch.setattr(server_mod, "recover_orphaned_proxy", rec.restore)
    monkeypatch.setattr(server_mod, "current_session_id", rec.current_session_id)
    monkeypatch.setattr(server_mod, "_proxy_gpo_locked", lambda: False)
    monkeypatch.setattr(server_mod, "_TRANSIENT_BACKOFF", 0.001)
    return rec


@pytest.fixture
def srv(wp, monkeypatch):
    handled = []
    serves = []

    def fake_handle_client(client, use_doh, frag, log_q, serve=None):
        handled.append(client)
        serves.append(serve)
        if s.gate is not None:  # lets a test keep its handlers busy
            s.gate.wait(10)
        client.close()

    monkeypatch.setattr(server_mod, "handle_client", fake_handle_client)
    s = ProxyServer()
    s.handled = handled
    s.serves = serves
    s.gate = None
    yield s
    if s.gate is not None:
        s.gate.set()
    # Close any real port a test left open, with the recorder back to normal.
    wp.restore_exc = wp.enable_exc = wp.enable_hook = None
    s.stop()


def run_loop(s, script, timeout=10):
    """Run s._run against a ScriptedListener as the session's accept thread
    and wait for the loop to end."""
    listener = ScriptedListener(s, script)
    s._sock = listener
    t = threading.Thread(target=s._run, args=(2, False), daemon=True)
    s._thread = t
    t.start()
    t.join(timeout)
    assert not t.is_alive(), "accept loop did not end"
    return listener


def assert_refused(port):
    # Windows retries the SYN after a RST on loopback, so a refusal can take
    # a second or two; a timeout instead means something still holds the port.
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(("127.0.0.1", port), timeout=10).close()


# ── _is_transient_accept_error ───────────────────────────────────────────────
@pytest.mark.parametrize("code", TRANSIENT_WSA)
def test_transient_wsa_code_as_errno(code):
    assert _is_transient_accept_error(OSError(code, "x"))


@pytest.mark.parametrize("code", TRANSIENT_WSA)
def test_transient_wsa_code_as_winerror(code):
    # errno deliberately unset, so only winerror can match.
    assert _is_transient_accept_error(types.SimpleNamespace(winerror=code, errno=None))


@pytest.mark.skipif(not IS_WINDOWS, reason="winerror is Windows-only")
@pytest.mark.parametrize("code", TRANSIENT_WSA)
def test_transient_real_windows_oserror(code):
    exc = OSError(None, "x", None, code)
    assert exc.winerror == code
    assert _is_transient_accept_error(exc)


@pytest.mark.parametrize("name", TRANSIENT_POSIX)
def test_transient_posix_errno(name):
    code = getattr(errno, name, None)
    if code is None:
        pytest.skip("errno.%s does not exist here" % name)
    assert _is_transient_accept_error(OSError(code, "x"))


@pytest.mark.parametrize("exc", [
    ConnectionResetError(10054, "reset"),
    ConnectionAbortedError(10053, "aborted"),
    ConnectionResetError(errno.ECONNRESET, "reset"),
    InterruptedError(errno.EINTR, "interrupted"),
    BlockingIOError(errno.EWOULDBLOCK, "would block"),
], ids=repr)
def test_transient_builtin_subclasses(exc):
    assert _is_transient_accept_error(exc)


@pytest.mark.parametrize("exc", [
    OSError(10038, "not a socket"),          # WSAENOTSOCK
    OSError(10022, "invalid argument"),      # WSAEINVAL
    OSError(errno.EBADF, "bad descriptor"),
    OSError(errno.EINVAL, "invalid"),
    OSError("no errno at all"),
    types.SimpleNamespace(winerror=10038, errno=None),
    types.SimpleNamespace(winerror=None, errno=None),
], ids=repr)
def test_fatal_errors(exc):
    assert not _is_transient_accept_error(exc)


# ── Accept loop: transient errors keep serving ───────────────────────────────
def test_transient_errors_then_success_keep_serving(srv, wp):
    errors = [OSError(c, "x") for c in TRANSIENT_WSA]
    errors += [OSError(getattr(errno, n), "x") for n in TRANSIENT_POSIX if hasattr(errno, n)]
    listener = run_loop(srv, errors + [CLIENT] + errors + [CLIENT])
    wait_until(lambda: len(srv.handled) == 2)
    lines = drain(srv.log_q)
    assert ERROR_LINE not in lines
    assert [lvl for lvl, _ in lines] == ["DEBUG"] * (2 * len(errors))
    assert all("transient error" in msg for _, msg in lines)
    assert wp.restores == 0
    assert listener.closed == 0
    assert srv.take_unexpected_stop() is False
    assert srv.has_session  # still the same session


def test_debug_line_names_the_error_code(srv):
    run_loop(srv, [ConnectionResetError(10054, "reset")])
    assert drain(srv.log_q) == [("DEBUG", "accept: transient error 10054, continuing")]


# ── Accept loop: fatal errors fail safe ──────────────────────────────────────
@pytest.mark.parametrize("fatal", [
    OSError(10038, "not a socket"),
    OSError(10022, "invalid argument"),
    OSError(errno.EBADF, "bad descriptor"),
    RuntimeError("an unexpected bug in the loop"),
], ids=repr)
def test_fatal_error_fails_safe(srv, wp, fatal):
    listener = run_loop(srv, [CLIENT, fatal, CLIENT])
    assert listener.closed == 1
    assert wp.restores == 1
    assert srv.take_unexpected_stop() is True
    assert srv.take_unexpected_stop() is False
    assert not srv.has_session
    assert srv._sock is None
    assert ERROR_LINE in drain(srv.log_q)
    assert listener.accepts == 2  # the CLIENT after the error was never accepted
    wait_until(lambda: len(srv.handled) == 1)


@pytest.mark.parametrize("result, line", [
    ("restored", RESTORED_AFTER_LINE),
    ("kept", KEPT_LINE),
    (None, None),
])
def test_fail_safe_reports_the_restore_outcome(srv, wp, result, line):
    wp.restore_result = result
    run_loop(srv, [OSError(10038, "x")])
    lines = drain(srv.log_q)
    assert lines[0] == ERROR_LINE
    info = [entry for entry in lines if entry[0] == "INFO"]
    assert info == ([line] if line else [])


def test_fail_safe_never_raises_when_restore_fails(srv, wp):
    wp.restore_exc = RuntimeError("registry exploded")
    listener = run_loop(srv, [OSError(10038, "x")])
    assert listener.closed == 1
    assert srv.take_unexpected_stop() is True
    assert not srv.has_session


def test_transient_errors_beyond_the_budget_fail_safe(srv, wp, monkeypatch):
    monkeypatch.setattr(server_mod, "_TRANSIENT_FAILURE_BUDGET", 0.2)
    monkeypatch.setattr(server_mod, "_TRANSIENT_BACKOFF", 0.01)

    def endless():
        while True:
            yield ConnectionResetError(10054, "reset")

    start = time.monotonic()
    listener = run_loop(srv, endless())
    elapsed = time.monotonic() - start
    assert 0.2 <= elapsed < 5
    assert listener.closed == 1
    assert wp.restores == 1
    assert srv.take_unexpected_stop() is True
    assert ERROR_LINE in drain(srv.log_q)


def test_quiet_timeout_resets_the_budget(srv, wp, monkeypatch):
    # Two isolated resets further apart than the budget on an idle proxy
    # (only quiet timeouts in between) are not a "persisting" error.
    monkeypatch.setattr(server_mod, "_TRANSIENT_FAILURE_BUDGET", 0.2)

    def quiet_second():
        time.sleep(0.3)
        return socket.timeout("timed out")

    listener = run_loop(srv, [ConnectionResetError(10054, "reset"), quiet_second,
                              ConnectionResetError(10054, "reset"), CLIENT])
    wait_until(lambda: len(srv.handled) == 1)
    assert listener.closed == 0
    assert wp.restores == 0
    assert srv.take_unexpected_stop() is False


def test_successful_accept_resets_the_budget(srv, wp, monkeypatch):
    monkeypatch.setattr(server_mod, "_TRANSIENT_FAILURE_BUDGET", 0.2)

    def later(item):
        def go():
            time.sleep(0.15)
            return item
        return go

    reset = ConnectionResetError(10054, "reset")
    listener = run_loop(srv, [reset, later(CLIENT), reset, later(reset), CLIENT])
    wait_until(lambda: len(srv.handled) == 2)
    assert listener.closed == 0
    assert wp.restores == 0


def test_error_after_stop_is_silent(srv, wp):
    def stop_then_fail():
        srv._stop.set()
        return OSError(10038, "socket closed by stop()")

    listener = run_loop(srv, [stop_then_fail])
    assert drain(srv.log_q) == []
    assert wp.restores == 0
    assert listener.closed == 0
    assert srv.take_unexpected_stop() is False


def test_fail_safe_leaves_a_newer_session_alone(srv, wp):
    # The loop's socket is no longer the server's (a Stop and a new Start got
    # there first, and the old thread missed the stop event): the new session
    # owns everything, so the dying old loop must not touch it.
    newer = FakeClient()  # stands in for the new session's socket

    def replaced_then_fail():
        srv._sock = newer
        return OSError(10038, "old socket closed")

    listener = run_loop(srv, [replaced_then_fail])
    assert srv._sock is newer and not newer.closed
    assert srv.has_session
    assert listener.closed == 0
    assert wp.restores == 0
    assert drain(srv.log_q) == []
    assert srv.take_unexpected_stop() is False


def test_log_lines_read_well_in_the_friendly_log():
    # The ERROR keeps the prefix logformat maps; the new lines match none of
    # its patterns by accident and pass through as written; DEBUG stays hidden.
    from sniper.logformat import friendly_format
    assert friendly_format(*ERROR_LINE) == ("ERROR", "Proxy stopped unexpectedly")
    assert friendly_format(*STOPPED_LINE) == ("OK", "Stopped — system proxy restored")
    for line in (RESTORED_AFTER_LINE, KEPT_LINE, CANCELLED_LINE):
        assert friendly_format(*line) == line
    assert friendly_format("DEBUG", "accept: transient error 10054, continuing") is None


# ── stop() ───────────────────────────────────────────────────────────────────
def test_stop_on_a_never_started_server_restores_quietly(srv, wp):
    srv.stop()
    assert wp.restores == 1
    assert drain(srv.log_q) == []


@pytest.mark.parametrize("result, line", [("restored", STOPPED_LINE), ("kept", KEPT_LINE)])
def test_stop_without_session_logs_only_a_real_restore(srv, wp, result, line):
    # E.g. a record the fail-safe could not restore is restored on close.
    wp.restore_result = result
    srv.stop()
    assert drain(srv.log_q) == [line]


def test_stop_twice_after_a_real_session(srv, wp):
    srv.start(0, 2, False)
    thread = srv._thread
    srv.stop()
    srv.stop()
    assert not thread.is_alive()
    assert wp.restores == 2
    lines = drain(srv.log_q)
    assert lines.count(STOPPED_LINE) == 1
    assert not srv.has_session and not srv.running


def test_stop_reports_kept(srv, wp):
    srv.start(0, 2, False)
    wp.restore_result = "kept"
    srv.stop()
    lines = drain(srv.log_q)
    assert KEPT_LINE in lines and STOPPED_LINE not in lines


def test_stop_after_fail_safe_is_a_quiet_no_op(srv, wp):
    run_loop(srv, [OSError(10038, "x")])
    drain(srv.log_q)
    srv.stop()
    assert wp.restores == 2
    assert drain(srv.log_q) == []


# ── start() ──────────────────────────────────────────────────────────────────
def test_start_on_port_zero_uses_the_real_port(srv, wp):
    seen = {}

    def check_served(addr):
        # The accept thread already runs, and the port takes connections,
        # at the moment clients get pointed at it.
        seen["running"] = srv.running
        socket.create_connection(("127.0.0.1", srv.port), timeout=5).close()

    wp.enable_hook = check_served
    srv.start(0, 2, False)
    assert isinstance(srv.port, int) and 0 < srv.port < 65536
    assert srv.addr == "127.0.0.1:%d" % srv.port
    assert wp.enables == [srv.addr]
    assert seen["running"] is True
    wait_until(lambda: len(srv.handled) == 1)
    lines = drain(srv.log_q)
    assert ("INFO", "Proxy started on 127.0.0.1:%d  |  fragment=2B  |  DoH=off"
            "  |  mode=safe" % srv.port) in lines


def test_start_twice_is_ignored(srv, wp):
    srv.start(0, 2, True)
    port = srv.port
    srv.start(0, 2, True)
    assert srv.port == port
    assert wp.enables == [srv.addr]


def test_start_that_fails_to_apply_cleans_up(srv, wp):
    wp.enable_exc = RuntimeError("registry exploded")
    with pytest.raises(RuntimeError):
        srv.start(0, 2, False)
    port = srv.port
    assert not srv.has_session
    assert srv._sock is None
    assert wp.restores == 1
    assert_refused(port)
    wp.enable_exc = None
    srv.start(port, 2, False)  # nothing left holding the port
    assert srv.running


def test_start_on_a_busy_port_raises_and_applies_nothing(srv, wp):
    other = ProxyServer()
    other.start(0, 2, False)
    try:
        enables = list(wp.enables)
        with pytest.raises(OSError):
            srv.start(other.port, 2, False)
        assert wp.enables == enables
        assert not srv.has_session
    finally:
        other.stop()


def test_start_clears_a_stale_unexpected_stop(srv, wp):
    run_loop(srv, [OSError(10038, "x")])
    srv.start(0, 2, False)
    # The UI must not flip the new session to "Stopped".
    assert srv.take_unexpected_stop() is False


# ── End to end on a real socket ──────────────────────────────────────────────
@pytest.mark.slow
def test_socket_closed_behind_the_loops_back_fails_safe(srv, wp):
    srv.start(0, 2, False)
    port = srv.port
    socket.create_connection(("127.0.0.1", port), timeout=5).close()
    srv._sock.close()  # without setting _stop
    wait_until(srv._unexpected_stop.is_set)
    assert srv.take_unexpected_stop() is True
    assert not srv.has_session
    assert wp.restores == 1
    assert ERROR_LINE in drain(srv.log_q)
    assert_refused(port)


@pytest.mark.slow
def test_fatal_error_on_an_open_socket_closes_the_port(srv, wp):
    real = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    real.bind(("127.0.0.1", 0))
    real.listen(16)
    port = real.getsockname()[1]
    # Clients can connect into the backlog: the port is held open.
    socket.create_connection(("127.0.0.1", port), timeout=5).close()

    class FatalAccept:
        def accept(self):
            raise OSError(10022, "invalid argument")

        def close(self):
            real.close()

    srv._sock = FatalAccept()
    t = threading.Thread(target=srv._run, args=(2, False), daemon=True)
    srv._thread = t
    t.start()
    t.join(10)
    assert srv.take_unexpected_stop() is True
    assert_refused(port)


@pytest.mark.slow
def test_start_again_on_the_same_port_after_fail_safe(srv, wp):
    # The v1.1.7 bug: the dead loop kept the port bound, so Start failed.
    srv.start(0, 2, False)
    port = srv.port
    srv._sock.close()
    wait_until(srv._unexpected_stop.is_set)
    srv.start(port, 2, False)
    assert srv.running and srv.addr == "127.0.0.1:%d" % port
    assert wp.enables == [srv.addr, srv.addr]
    socket.create_connection(("127.0.0.1", port), timeout=5).close()


# ── Session-end hooks ────────────────────────────────────────────────────────
def test_session_ending_restores_without_a_session(srv, wp):
    srv.session_ending()
    assert wp.restores == 1
    assert srv._suspended_for_session_end is False
    assert drain(srv.log_q) == []


def test_session_ending_then_cancelled_reapplies_the_same_address(srv, wp):
    srv.start(0, 2, False)
    addr = srv.addr
    drain(srv.log_q)
    srv.session_ending()
    assert wp.restores == 1
    assert srv._applied is False
    # The server keeps running in case the sign-out is cancelled.
    assert srv.running
    socket.create_connection(("127.0.0.1", srv.port), timeout=5).close()
    srv.session_end_cancelled()
    assert wp.enables == [addr, addr]
    assert srv._applied is True
    assert drain(srv.log_q) == [CANCELLED_LINE]
    srv.session_end_cancelled()  # a second one has nothing to re-apply
    assert wp.enables == [addr, addr]


def test_session_ending_twice_is_harmless(srv, wp):
    srv.start(0, 2, False)
    srv.session_ending()  # WM_QUERYENDSESSION
    srv.session_ending()  # WM_ENDSESSION(TRUE)
    assert wp.restores == 2
    assert srv.running


def test_cancelled_without_ending_does_nothing(srv, wp):
    srv.start(0, 2, False)
    drain(srv.log_q)
    srv.session_end_cancelled()
    assert wp.enables == [srv.addr]
    assert drain(srv.log_q) == []


def test_cancelled_after_stop_does_not_reapply(srv, wp):
    srv.start(0, 2, False)
    srv.session_ending()
    srv.stop()
    srv.session_end_cancelled()
    assert wp.enables == [srv.addr]
    assert wp.ops[-1] == ("restore",)


def test_cancelled_after_fail_safe_does_not_reapply(srv, wp):
    srv.start(0, 2, False)
    srv.session_ending()
    srv._sock.close()
    wait_until(srv._unexpected_stop.is_set)
    srv.session_end_cancelled()
    assert wp.enables == [srv.addr]


def test_cancelled_with_a_dead_accept_thread_does_not_reapply(srv, wp):
    # A session whose accept thread is gone without the fail-safe or a Stop
    # having run: pointing clients at it again would strand them.
    srv.start(0, 2, False)
    accept_thread = srv._thread
    srv.session_ending()
    srv._stop.set()  # the loop ends quietly; the session itself remains
    wait_until(lambda: not accept_thread.is_alive())
    assert srv.has_session and not srv.running
    srv.session_end_cancelled()
    assert wp.enables == [srv.addr]
    assert srv._suspended_for_session_end is False


def test_hooks_never_raise(srv, wp):
    srv.start(0, 2, False)
    wp.restore_exc = RuntimeError("restore exploded")
    wp.enable_exc = RuntimeError("enable exploded")
    srv.session_ending()
    srv.session_end_cancelled()
    assert len(wp.enables) == 2  # the re-apply was attempted, and failed
    wp.enable_exc = None
    real_q, srv.log_q = srv.log_q, None  # even the log line can fail
    srv.session_ending()
    srv.session_end_cancelled()
    assert len(wp.enables) == 3
    srv.log_q = real_q


def test_session_ending_restores_even_if_the_lock_is_stuck(srv, wp, monkeypatch):
    monkeypatch.setattr(server_mod, "_SESSION_LOCK_TIMEOUT", 0.2)
    held, release = threading.Event(), threading.Event()

    def hold():
        with srv._sys_lock:
            held.set()
            release.wait(10)

    t = threading.Thread(target=hold, daemon=True)
    t.start()
    held.wait(5)
    try:
        start = time.monotonic()
        srv.session_ending()
        assert time.monotonic() - start < 5
        assert wp.restores == 1
        srv._suspended_for_session_end = True
        srv.session_end_cancelled()
        assert wp.enables == []  # re-applying without the lock is never safe
        assert srv._suspended_for_session_end is False
        assert drain(srv.log_q)[-1][0] == "WARNING"
    finally:
        release.set()
        t.join(5)


def test_reapply_after_cancel_never_lands_after_stop(srv, wp):
    # session_end_cancelled re-applies while stop() runs concurrently. stop()
    # must wait for the re-apply to finish and then restore, never restore in
    # the middle and let the re-apply land last on a closed port.
    srv.start(0, 2, False)
    accept_thread = srv._thread
    srv.session_ending()
    in_enable, release = threading.Event(), threading.Event()

    def slow_enable(addr):
        in_enable.set()
        release.wait(10)

    wp.enable_hook = slow_enable
    canceller = threading.Thread(target=srv.session_end_cancelled, daemon=True)
    canceller.start()
    assert in_enable.wait(5)
    stopper = threading.Thread(target=srv.stop, daemon=True)
    stopper.start()
    wait_until(lambda: not srv.has_session)
    wait_until(lambda: not accept_thread.is_alive())
    stopper.join(0.5)
    assert stopper.is_alive(), "stop() restored while a re-apply was in progress"
    release.set()
    canceller.join(5)
    stopper.join(5)
    assert wp.ops[-2:] == [("enable-done", srv.addr), ("restore",)]


def test_stop_and_session_ending_concurrently(srv, wp):
    errors = []

    def call(fn, barrier):
        try:
            barrier.wait(5)
            fn()
        except Exception as e:  # pragma: no cover - reported below
            errors.append(e)

    for _ in range(20):
        srv.start(0, 2, False)
        barrier = threading.Barrier(2)
        threads = [threading.Thread(target=call, args=(fn, barrier))
                   for fn in (srv.stop, srv.session_ending)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        assert not srv.has_session
        assert wp.ops[-1] == ("restore",)
        srv.session_end_cancelled()  # nothing left to re-apply
        assert wp.ops[-1] == ("restore",)
    assert errors == []


# ── Safe mode and Compatibility mode ─────────────────────────────────────────
@pytest.fixture
def live_srv(wp):
    """A ProxyServer with the real connection handler (winproxy is still the
    recorder), for what a client on a real socket gets."""
    s = ProxyServer()
    yield s
    wp.restore_exc = wp.enable_exc = wp.enable_hook = None
    s.stop()


def fetch(url, timeout=10):
    """GET url directly, never through a proxy from the environment."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=timeout) as r:
        return r.status, r.headers, r.read()


def fetch_status(url):
    try:
        return fetch(url)[0]
    except urllib.error.HTTPError as e:
        e.close()
        return e.code


def recv_all(sock):
    data = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return data
        data += chunk


def started_line(port, frag=2, doh="off", mode="safe"):
    return ("INFO", "Proxy started on 127.0.0.1:%d  |  fragment=%dB  |  DoH=%s"
            "  |  mode=%s" % (port, frag, doh, mode))


def limit_line(n):
    return (LIMIT_LINE[0], LIMIT_LINE[1] % n)


def test_safe_mode_applies_and_serves_its_pac_script(live_srv, wp):
    live_srv.start(0, 2, False)
    port = live_srv.port
    assert wp.enables == [live_srv.addr]
    url = wp.pac_urls[0]
    assert re.match(PAC_URL_RX % port, url), url
    assert live_srv.pac_url == url
    status, headers, body = fetch(url)
    assert status == 200
    assert headers["Content-Type"] == "application/x-ns-proxy-autoconfig"
    assert body.decode("ascii") == build_pac(port)
    lines = drain(live_srv.log_q)
    # The fetch is no connection: only the start line is above DEBUG.
    assert [line for line in lines if line[0] != "DEBUG"] == [started_line(port)]


@pytest.mark.parametrize("compat, text", [(False, "safe mode"),
                                          (True, "compatibility mode")])
def test_start_line_reads_well_in_the_friendly_log(srv, wp, compat, text):
    from sniper.logformat import friendly_format
    srv.start(0, 2, True, compat=compat)
    line = [entry for entry in drain(srv.log_q) if entry[1].startswith("Proxy started")]
    assert friendly_format(*line[0]) == (
        "OK", "Started — listening on port %d  ·  fragment 2B  ·  secure DNS  ·  %s"
        % (srv.port, text))


def test_safe_mode_answers_other_paths_with_404(live_srv, wp):
    live_srv.start(0, 2, False)
    base = "http://127.0.0.1:%d" % live_srv.port
    assert fetch_status(base + "/sniper-0000000000000000.pac") == 404
    assert fetch_status(base + "/") == 404


def test_compat_mode_applies_the_static_proxy_and_serves_no_script(live_srv, wp):
    live_srv.start(0, 2, True, compat=True)
    port = live_srv.port
    assert wp.enables == [live_srv.addr]
    assert wp.pac_urls == [None]
    assert live_srv.pac_url is None
    assert live_srv._serve.pac_path is None
    assert fetch_status("http://127.0.0.1:%d/sniper-0123456789abcdef.pac" % port) == 404
    assert started_line(port, doh="on", mode="compat") in drain(live_srv.log_q)


def test_every_session_gets_a_new_script_url(live_srv, wp):
    live_srv.start(0, 2, False)
    first, port = live_srv.pac_url, live_srv.port
    assert fetch_status(first) == 200
    live_srv.stop()
    live_srv.start(port, 2, False)  # same port, right after the PAC fetch
    second = live_srv.pac_url
    assert second != first
    assert wp.pac_urls == [first, second]
    # The old session's script went with it.
    assert fetch_status(first) == 404
    assert fetch_status(second) == 200


def test_start_that_fails_to_build_the_script_closes_the_port(srv, wp, monkeypatch):
    import sniper.pac
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    def broken(port):
        raise ValueError("no script")

    monkeypatch.setattr(server_mod, "build_pac", broken)
    with pytest.raises(ValueError):
        srv.start(port, 2, False)
    assert wp.enables == []
    assert not srv.has_session and srv._sock is None
    monkeypatch.setattr(server_mod, "build_pac", sniper.pac.build_pac)
    srv.start(port, 2, False)  # nothing left holding the port
    assert srv.running and srv.port == port


def test_switching_modes_between_sessions(srv, wp):
    srv.start(0, 2, False, compat=True)
    srv.stop()
    srv.start(0, 2, False)
    assert wp.pac_urls[0] is None
    assert re.match(PAC_URL_RX % srv.port, wp.pac_urls[1])
    srv.stop()
    srv.start(0, 2, False, compat=True)
    assert srv.pac_url is None and wp.pac_urls[2] is None


def test_handlers_get_the_sessions_serve_config(srv, wp):
    srv.start(0, 2, False)
    socket.create_connection(("127.0.0.1", srv.port), timeout=5).close()
    wait_until(lambda: srv.serves)
    serve = srv.serves[0]
    assert serve is srv._serve
    assert serve.listen_port == srv.port
    assert srv.pac_url.endswith(serve.pac_path)
    assert serve.pac_body == build_pac(srv.port).encode("ascii")


@pytest.mark.parametrize("compat", [False, True])
def test_cancelled_sign_out_reapplies_the_same_mode_and_url(srv, wp, compat):
    srv.start(0, 2, False, compat=compat)
    url = srv.pac_url
    srv.session_ending()
    srv.session_end_cancelled()
    assert wp.enables == [srv.addr, srv.addr]
    assert wp.pac_urls == [url, url]
    assert (url is None) == compat


# ── Backpressure ─────────────────────────────────────────────────────────────
def start_loop(s, script):
    """Like run_loop, but leaves the loop running."""
    listener = ScriptedListener(s, script)
    s._sock = listener
    t = threading.Thread(target=s._run, args=(2, False), daemon=True)
    s._thread = t
    t.start()
    return listener, t


def test_at_the_limit_the_loop_stops_accepting(srv, wp, monkeypatch):
    # Nobody is accepted and closed: while every slot is busy, accept() is
    # not even called, so waiting clients stay in the kernel backlog.
    monkeypatch.setattr(server_mod, "MAX_CONNECTIONS", 1)
    monkeypatch.setattr(server_mod, "_SLOT_WAIT", 0.02)
    srv.gate = threading.Event()
    listener, t = start_loop(srv, [CLIENT, CLIENT])
    seen = []
    wait_until(lambda: seen.extend(drain(srv.log_q)) or limit_line(1) in seen)
    # The loop now waits; give it many slot-wait rounds to misbehave in.
    deadline = time.monotonic() + 0.3
    while time.monotonic() < deadline:
        assert listener.accepts == 1
        time.sleep(0.02)
    srv.gate.set()
    t.join(10)
    assert not t.is_alive()
    assert len(srv.handled) == 2 and listener.accepts == 3
    # Each client was closed once, by its handler, never by the loop.
    assert [c.close_count for c in listener.clients] == [1, 1]
    seen.extend(drain(srv.log_q))
    assert seen.count(limit_line(1)) == 1  # many rounds, one line
    assert not any("refusing" in msg for _, msg in seen)


def test_limit_warning_repeats_only_after_the_interval(srv, wp, monkeypatch):
    monkeypatch.setattr(server_mod, "MAX_CONNECTIONS", 1)
    monkeypatch.setattr(server_mod, "_SLOT_WAIT", 0.01)
    monkeypatch.setattr(server_mod, "_LIMIT_WARNING_INTERVAL", 0.1)
    srv.gate = threading.Event()
    seen = []
    start = time.monotonic()
    listener, t = start_loop(srv, [CLIENT, CLIENT])
    wait_until(lambda: seen.extend(drain(srv.log_q)) or seen.count(limit_line(1)) >= 3)
    srv.gate.set()
    t.join(10)
    elapsed = time.monotonic() - start
    seen.extend(drain(srv.log_q))
    # Repeated while the limit lasts, but never more than once per interval.
    assert 3 <= seen.count(limit_line(1)) <= elapsed / 0.1 + 1


@pytest.mark.parametrize("error", [socket.timeout("timed out"),
                                   ConnectionResetError(10054, "reset")], ids=repr)
def test_a_failed_accept_gives_its_slot_back(srv, wp, monkeypatch, error):
    # With one slot, a leaked one would stall the loop for good.
    monkeypatch.setattr(server_mod, "MAX_CONNECTIONS", 1)
    listener = run_loop(srv, [error] * 5 + [CLIENT, error, CLIENT])
    wait_until(lambda: len(srv.handled) == 2)
    assert listener.accepts == 9
    assert wp.restores == 0


def test_a_handler_that_cannot_start_gives_its_slot_back(srv, wp, monkeypatch):
    class NoThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise RuntimeError("can't start new thread")

    monkeypatch.setattr(server_mod, "MAX_CONNECTIONS", 1)
    # server's own view of the threading module, with only Thread replaced.
    fake_threading = types.SimpleNamespace(**{
        name: getattr(threading, name) for name in dir(threading)
        if not name.startswith("__")})
    fake_threading.Thread = NoThread
    monkeypatch.setattr(server_mod, "threading", fake_threading)
    listener = run_loop(srv, [CLIENT, CLIENT, CLIENT])
    assert listener.accepts == 4
    assert [c.close_count for c in listener.clients] == [1, 1, 1]
    assert srv.handled == []
    assert wp.restores == 0


def test_waiting_for_a_slot_does_not_count_towards_the_error_budget(srv, wp, monkeypatch):
    monkeypatch.setattr(server_mod, "MAX_CONNECTIONS", 1)
    monkeypatch.setattr(server_mod, "_TRANSIENT_FAILURE_BUDGET", 0.2)
    monkeypatch.setattr(server_mod, "_SLOT_WAIT", 0.02)
    srv.gate = threading.Event()
    reset = ConnectionResetError(10054, "reset")

    def hold_then_client():
        # The first client's handler keeps the only slot for longer than the
        # whole budget, so the loop waits that long before its next accept.
        threading.Timer(0.5, srv.gate.set).start()
        return CLIENT

    listener = run_loop(srv, [reset, hold_then_client, reset, reset, CLIENT])
    wait_until(lambda: len(srv.handled) == 2)
    assert listener.closed == 0
    assert wp.restores == 0
    assert srv.take_unexpected_stop() is False


@pytest.mark.slow
def test_over_the_limit_clients_wait_instead_of_being_reset(live_srv, wp, monkeypatch):
    monkeypatch.setattr(server_mod, "MAX_CONNECTIONS", 2)
    live_srv.start(0, 2, False)
    port, path = live_srv.port, live_srv._serve.pac_path
    seen = []
    idle = [socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(2)]
    third = None
    try:
        # Both slots belong to handlers waiting for a request that never
        # comes, so the loop has stopped accepting.
        wait_until(lambda: seen.extend(drain(live_srv.log_q)) or limit_line(2) in seen)
        third = socket.create_connection(("127.0.0.1", port), timeout=5)  # backlog
        third.sendall(b"GET " + path.encode("ascii") + b" HTTP/1.1\r\nHost: x\r\n\r\n")
        third.settimeout(1.5)
        # No reply, and no RST (ConnectionResetError) or EOF (b"") either.
        with pytest.raises(socket.timeout):
            third.recv(1)
        idle[0].close()  # its handler ends and frees a slot
        third.settimeout(5)
        start = time.monotonic()
        data = recv_all(third)
        assert time.monotonic() - start < 5
        assert data.startswith(b"HTTP/1.1 200 OK\r\n")
        assert data.endswith(build_pac(port).encode("ascii"))
    finally:
        for s in idle + [third]:
            if s is not None:
                s.close()
    seen.extend(drain(live_srv.log_q))
    assert seen.count(limit_line(2)) == 1
    assert not any("refusing" in msg for _, msg in seen)


@pytest.mark.slow
def test_stop_while_waiting_for_a_slot(live_srv, wp, monkeypatch):
    monkeypatch.setattr(server_mod, "MAX_CONNECTIONS", 1)
    live_srv.start(0, 2, False)
    accept_thread = live_srv._thread
    seen = []
    idle = socket.create_connection(("127.0.0.1", live_srv.port), timeout=5)
    try:
        wait_until(lambda: seen.extend(drain(live_srv.log_q)) or limit_line(1) in seen)
        start = time.monotonic()
        live_srv.stop()
        # The loop notices the stop within one slot wait, well inside
        # stop()'s 3 s join.
        assert time.monotonic() - start < 2.5
        assert not accept_thread.is_alive()
        assert wp.restores == 1
    finally:
        idle.close()


# ── Sessions and the guardian ────────────────────────────────────────────────
NO_GUARD_LINE = ("WARNING", "Safety guard could not be started; your proxy settings "
                 "will still be restored when SNIper closes or starts again.")
ALREADY_LINE = ("INFO", "A previous unclean exit was detected; your proxy settings "
                "were already back to normal.")


@pytest.mark.parametrize("compat", [False, True])
def test_start_guards_its_session(srv, wp, guardian_spawns, compat):
    srv.start(0, 2, False, compat=compat)
    sid = srv.session_id
    assert re.fullmatch(r"[0-9a-f]{16}", sid)
    assert wp.session_ids == [sid]          # the record names this session...
    assert guardian_spawns.calls == [sid]   # ...and so does its guardian
    assert NO_GUARD_LINE not in drain(srv.log_q)


def test_the_guardian_starts_only_after_the_apply_finished(srv, wp, guardian_spawns,
                                                           monkeypatch):
    def spawn(session_id):
        wp._log("spawn", session_id)
        return True
    monkeypatch.setattr(server_mod, "spawn_guardian", spawn)
    srv.start(0, 2, False)
    assert [op[0] for op in wp.ops] == ["enable", "enable-done", "spawn"]


def test_every_session_gets_a_new_id_and_guardian(srv, wp, guardian_spawns):
    srv.start(0, 2, False)
    first = srv.session_id
    srv.stop()
    srv.start(0, 2, False)
    second = srv.session_id
    assert first != second
    assert guardian_spawns.calls == [first, second]
    assert wp.session_ids == [first, second]


@pytest.mark.parametrize("compat", [False, True])
def test_cancelled_sign_out_starts_a_new_session_and_guardian(srv, wp, guardian_spawns,
                                                              compat):
    # The old guardian left when session_ending() cleared its record.
    srv.start(0, 2, False, compat=compat)
    first = srv.session_id
    srv.session_ending()
    assert wp.current is None
    srv.session_end_cancelled()
    second = srv.session_id
    assert second != first
    assert wp.session_ids == [first, second]
    assert guardian_spawns.calls == [first, second]


def test_no_guardian_when_the_record_is_not_this_sessions(srv, wp, guardian_spawns):
    # Group Policy locked, or the record write failed: nothing to guard, and
    # nothing to warn about either.
    wp.writes_record = False
    srv.start(0, 2, False)
    assert guardian_spawns.calls == []
    assert NO_GUARD_LINE not in drain(srv.log_q)
    assert srv.running


def test_a_guardian_that_cannot_start_is_a_warning_only(srv, wp, guardian_spawns):
    guardian_spawns.result = False
    srv.start(0, 2, False)
    assert srv.running and srv.has_session
    lines = drain(srv.log_q)
    assert lines.count(NO_GUARD_LINE) == 1
    assert wp.restores == 0  # the session stays applied


@pytest.mark.parametrize("broken", ["spawn", "current_session_id"])
def test_a_failing_guard_never_fails_the_start(srv, wp, monkeypatch, broken):
    def boom(*args):
        raise RuntimeError("exploded")
    monkeypatch.setattr(server_mod, "spawn_guardian" if broken == "spawn"
                        else "current_session_id", boom)
    srv.start(0, 2, False)
    assert srv.running
    assert NO_GUARD_LINE in drain(srv.log_q)
    assert wp.restores == 0


def test_a_guardian_failure_in_the_cancelled_path_never_raises(srv, wp, guardian_spawns):
    srv.start(0, 2, False)
    srv.session_ending()
    guardian_spawns.result = False
    drain(srv.log_q)
    srv.session_end_cancelled()
    lines = drain(srv.log_q)
    assert NO_GUARD_LINE in lines and CANCELLED_LINE in lines


def test_recover_reports_already(srv, wp):
    wp.restore_result = "already"
    srv.recover()
    assert drain(srv.log_q) == [ALREADY_LINE]


@pytest.mark.parametrize("session", [False, True])
def test_stop_treats_already_like_restored(srv, wp, session):
    if session:
        srv.start(0, 2, False)
        drain(srv.log_q)
    wp.restore_result = "already"
    srv.stop()
    assert drain(srv.log_q) == [STOPPED_LINE]


def test_new_lines_read_well_in_the_friendly_log():
    from sniper.logformat import friendly_format
    for line in (NO_GUARD_LINE, ALREADY_LINE):
        assert friendly_format(*line) == line
