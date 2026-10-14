"""Tests for winproxy's cross-process state mutex, with real processes.

The record can be acted on by SNIper and its guardian at the same time, so
every read-decide-write runs under a named mutex. A holder delays the other
process; one that was killed while holding it (WAIT_ABANDONED) does not; and
after a timeout the operation goes ahead anyway, because restoring late beats
not restoring. The mutex is the registry sandbox's own, so a real SNIper on
this machine is never involved.
"""
from __future__ import annotations

import ctypes
import subprocess
import sys
import threading
import time

import pytest

import sniper.winproxy as winproxy
from sniper.compat import IS_WINDOWS

pytestmark = [pytest.mark.skipif(not IS_WINDOWS, reason="named mutexes are Win32"),
              pytest.mark.windows_integration]

ADDR = "127.0.0.1:8881"

# hold:    take the mutex, say "held <wait result>", keep it until a line
#          arrives on stdin (or until killed), then release it and exit
# try:     try to take it without waiting; print the wait result and exit
_HOLDER = r"""
import ctypes, sys
from ctypes import wintypes
k = ctypes.WinDLL("kernel32", use_last_error=True)
k.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
k.CreateMutexW.restype = ctypes.c_void_p
k.WaitForSingleObject.argtypes = [ctypes.c_void_p, wintypes.DWORD]
k.WaitForSingleObject.restype = wintypes.DWORD
k.ReleaseMutex.argtypes = [ctypes.c_void_p]
k.ReleaseMutex.restype = wintypes.BOOL
h = k.CreateMutexW(None, False, sys.argv[1])
if sys.argv[2] == "try":
    print(k.WaitForSingleObject(h, 0), flush=True)
    sys.exit(0)
print("held %d" % k.WaitForSingleObject(h, 10000), flush=True)
sys.stdin.readline()
k.ReleaseMutex(h)
"""
WAIT_OBJECT_0, WAIT_ABANDONED, WAIT_TIMEOUT = 0, 0x80, 0x102


@pytest.fixture
def holder(registry_sandbox):
    procs = []

    def start():
        p = subprocess.Popen([sys.executable, "-c", _HOLDER, registry_sandbox.mutex_name,
                              "hold"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             universal_newlines=True)
        procs.append(p)
        assert p.stdout.readline().strip() == "held 0"
        return p

    yield start
    for p in procs:
        if p.poll() is None:
            p.kill()
        p.wait(10)
        p.stdin.close()
        p.stdout.close()


def try_acquire(name):
    """What another process gets when it tries the mutex without waiting."""
    out = subprocess.run([sys.executable, "-c", _HOLDER, name, "try"],
                         stdout=subprocess.PIPE, universal_newlines=True, timeout=30)
    return int(out.stdout.strip())


def release(p):
    p.stdin.write("go\n")
    p.stdin.flush()


def test_the_sandbox_has_its_own_mutex(registry_sandbox):
    assert winproxy._STATE_MUTEX_NAME == registry_sandbox.mutex_name
    assert winproxy._STATE_MUTEX_NAME.startswith("SNIper_proxy_state_")
    assert winproxy._STATE_MUTEX_NAME != "SNIper_proxy_state"


@pytest.mark.slow
def test_a_holder_delays_restore_until_it_lets_go(registry_sandbox, holder):
    winproxy.proxy_enable(ADDR)
    footprint = registry_sandbox.live()
    p = holder()
    result = {}

    def restore():
        start = time.monotonic()
        result["outcome"] = winproxy.proxy_restore()
        result["elapsed"] = time.monotonic() - start

    t = threading.Thread(target=restore, daemon=True)
    t.start()
    t.join(1.5)
    # Still waiting, and nothing touched while the other process holds it.
    assert t.is_alive()
    assert registry_sandbox.live() == footprint
    assert registry_sandbox.record() is not None
    release(p)
    t.join(5)
    assert not t.is_alive()
    assert result["outcome"] == "restored"
    assert 1.5 <= result["elapsed"] < 5.0


@pytest.mark.slow
def test_after_the_timeout_restore_goes_ahead_anyway(registry_sandbox, holder, monkeypatch):
    monkeypatch.setattr(winproxy, "_STATE_LOCK_TIMEOUT_MS", 200)
    winproxy.proxy_enable(ADDR)
    p = holder()  # holds it for as long as this test wants
    start = time.monotonic()
    assert winproxy.proxy_restore() == "restored"
    elapsed = time.monotonic() - start
    assert 0.18 <= elapsed < 3.0
    assert registry_sandbox.record() is None
    assert p.poll() is None  # the holder never let go
    release(p)


class SpyKernel32:
    """winproxy's mutex API, recording what each wait returned."""

    def __init__(self, real):
        self.real = real
        self.waits = []

    def __getattr__(self, name):
        return getattr(self.real, name)

    def WaitForSingleObject(self, handle, ms):
        result = self.real.WaitForSingleObject(handle, ms)
        self.waits.append(result)
        return result


@pytest.fixture
def spy(monkeypatch):
    s = SpyKernel32(winproxy._bind_mutex_api())
    monkeypatch.setattr(winproxy, "_mutex_api", s)
    return s


def open_mutex(name):
    """A handle to the named mutex, without waiting for it."""
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    k.CreateMutexW.restype = ctypes.c_void_p
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    k.CloseHandle.restype = ctypes.c_int
    handle = k.CreateMutexW(None, False, name)
    assert handle
    return handle, lambda: k.CloseHandle(handle)


@pytest.mark.slow
def test_a_holder_killed_mid_operation_does_not_block(registry_sandbox, holder, spy):
    # A named mutex exists only while someone has a handle to it, so a
    # killed holder leaves it abandoned only if another handle keeps it
    # alive, as a SNIper or guardian waiting for it at that moment does.
    name = registry_sandbox.mutex_name
    winproxy.proxy_enable(ADDR)
    _, close_keeper = open_mutex(name)
    try:
        p = holder()
        p.kill()  # TerminateProcess while it holds the mutex
        p.wait(10)
        spy.waits.clear()
        start = time.perf_counter()
        with winproxy._state_lock() as acquired:
            elapsed = time.perf_counter() - start
            assert acquired  # WAIT_ABANDONED counts as acquired...
        assert spy.waits == [WAIT_ABANDONED]
        assert elapsed < 1.0
        # ...and is released again like any other hold.
        assert try_acquire(name) == WAIT_OBJECT_0
        assert winproxy.proxy_restore() == "restored"
    finally:
        close_keeper()


@pytest.mark.slow
def test_a_waiter_proceeds_at_once_when_the_holder_is_killed(registry_sandbox, holder,
                                                            spy):
    winproxy.proxy_enable(ADDR)
    p = holder()
    spy.waits.clear()
    result = {}

    def restore():
        result["outcome"] = winproxy.proxy_restore()
        result["done"] = time.perf_counter()

    t = threading.Thread(target=restore, daemon=True)
    t.start()
    t.join(0.5)
    assert t.is_alive()  # waiting for the holder
    killed = time.perf_counter()
    p.kill()
    t.join(5)
    assert not t.is_alive()
    assert result["outcome"] == "restored"
    assert result["done"] - killed < 1.0  # not the 5 s timeout: it got the mutex
    assert spy.waits == [WAIT_ABANDONED]


def test_the_lock_is_released_after_every_operation(registry_sandbox):
    # The keeper handle keeps the mutex in existence between operations, so a
    # hold that was never released would still be there for try_acquire to
    # run into (without it, closing the last handle destroys the mutex).
    name = registry_sandbox.mutex_name
    _, close_keeper = open_mutex(name)
    try:
        winproxy.proxy_enable(ADDR)
        assert try_acquire(name) == WAIT_OBJECT_0
        assert winproxy.current_session_id()
        assert try_acquire(name) == WAIT_OBJECT_0
        assert winproxy.proxy_restore() == "restored"
        assert try_acquire(name) == WAIT_OBJECT_0
        # Also when the body raises.
        with pytest.raises(RuntimeError):
            with winproxy._state_lock():
                raise RuntimeError("boom")
        assert try_acquire(name) == WAIT_OBJECT_0
    finally:
        close_keeper()


def test_the_lock_is_held_during_the_operation(registry_sandbox):
    name = registry_sandbox.mutex_name
    with winproxy._state_lock() as acquired:
        assert acquired
        assert try_acquire(name) == WAIT_TIMEOUT
    assert try_acquire(name) == WAIT_OBJECT_0


def test_threads_of_one_process_are_serialized(registry_sandbox):
    # A mutex belongs to a thread: the UI and session-watcher threads of one
    # SNIper exclude each other too.
    inside, release_it = threading.Event(), threading.Event()
    order = []

    def first():
        with winproxy._state_lock():
            inside.set()
            release_it.wait(10)
            order.append("first")

    t = threading.Thread(target=first, daemon=True)
    t.start()
    assert inside.wait(5)
    done = threading.Event()

    def second():
        with winproxy._state_lock():
            order.append("second")
        done.set()

    threading.Thread(target=second, daemon=True).start()
    assert not done.wait(0.3)  # blocked while the first thread holds it
    assert order == []
    release_it.set()
    assert done.wait(5)
    assert order == ["first", "second"]
    t.join(5)


def test_without_the_mutex_api_the_operation_still_runs(registry_sandbox, monkeypatch):
    def broken():
        raise OSError("kernel32 is gone")
    monkeypatch.setattr(winproxy, "_bind_mutex_api", broken)
    with winproxy._state_lock() as acquired:
        assert acquired is False
    winproxy.proxy_enable(ADDR)
    assert winproxy.proxy_restore() == "restored"


def test_the_mutex_api_is_fully_bound():
    k = winproxy._bind_mutex_api()
    for name in ("CreateMutexW", "WaitForSingleObject", "ReleaseMutex", "CloseHandle"):
        fn = getattr(k, name)
        assert fn.argtypes is not None and fn.restype is not None, name
    assert k.CreateMutexW.restype is ctypes.c_void_p
    assert k.WaitForSingleObject.argtypes[0] is ctypes.c_void_p
    assert k is not ctypes.windll.kernel32  # a private binding
