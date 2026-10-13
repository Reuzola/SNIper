"""Tests for sniper.server.ProxyServer: the accept loop's error handling and
fail-safe, the idempotent stop(), and the session-end hooks.

winproxy is never reached: proxy_enable / proxy_restore are replaced by a
recorder, so nothing here can touch any registry. Real sockets on 127.0.0.1
are used where the point is what a client actually experiences.
"""
from __future__ import annotations

import errno
import socket
import threading
import time
import types

import pytest

import sniper.server as server_mod
from helpers import wait_until
from sniper.compat import IS_WINDOWS
from sniper.server import ProxyServer, _is_transient_accept_error

ERROR_LINE = ("ERROR", "Accept error — proxy stopped unexpectedly.")
STOPPED_LINE = ("INFO", "Proxy stopped. Windows proxy restored.")
KEPT_LINE = ("INFO", "Proxy server stopped; your manual proxy change was left in place.")
RESTORED_AFTER_LINE = ("INFO", "Windows proxy restored after the unexpected stop.")
CANCELLED_LINE = ("INFO", "Sign-out was cancelled — system proxy re-applied.")

TRANSIENT_WSA = [10004, 10024, 10035, 10053, 10054, 10055]
TRANSIENT_POSIX = ["EINTR", "EMFILE", "ENFILE", "ENOBUFS", "ECONNABORTED",
                   "ECONNRESET", "EAGAIN", "EWOULDBLOCK"]


# ── Recorders and fakes ──────────────────────────────────────────────────────
class WinproxyRecorder:
    """Stands in for proxy_enable / proxy_restore and records each call in
    order. "enable-done" marks when an enable returned, so tests can tell
    whether a restore landed before or after an apply finished."""

    def __init__(self):
        self.ops = []
        self.lock = threading.Lock()
        self.restore_result = None
        self.restore_exc = None
        self.enable_exc = None
        self.enable_hook = None

    def _log(self, *op):
        with self.lock:
            self.ops.append(op)

    def enable(self, addr):
        self._log("enable", addr)
        if self.enable_hook:
            self.enable_hook(addr)
        if self.enable_exc:
            raise self.enable_exc
        self._log("enable-done", addr)
        return None

    def restore(self):
        self._log("restore")
        if self.restore_exc:
            raise self.restore_exc
        return self.restore_result

    @property
    def enables(self):
        return [op[1] for op in self.ops if op[0] == "enable"]

    @property
    def restores(self):
        return sum(1 for op in self.ops if op[0] == "restore")


class FakeClient:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


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
        return FakeClient(), ("127.0.0.1", 50000)

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
    monkeypatch.setattr(server_mod, "_proxy_gpo_locked", lambda: False)
    monkeypatch.setattr(server_mod, "_TRANSIENT_BACKOFF", 0.001)
    return rec


@pytest.fixture
def srv(wp, monkeypatch):
    handled = []

    def fake_handle_client(client, use_doh, frag, log_q):
        handled.append(client)
        client.close()

    monkeypatch.setattr(server_mod, "handle_client", fake_handle_client)
    s = ProxyServer()
    s.handled = handled
    yield s
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
            % srv.port) in lines


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
