"""Tests for sniper.procutil: process identity (PID + creation time) and the
handle waits the guardian is built on.

The Windows tests run real child processes (killed in finally); the rest
check the off-Windows fallbacks on any OS.
"""
from __future__ import annotations

import ctypes
import gc
import os
import subprocess
import sys

import pytest

import sniper.procutil as procutil
from helpers import wait_until
from sniper.compat import IS_WINDOWS

windows_only = pytest.mark.skipif(not IS_WINDOWS, reason="needs Win32 process handles")
_SRC = os.path.dirname(os.path.dirname(os.path.abspath(procutil.__file__)))

# A child that reports its own identity (procutil's GetCurrentProcess path),
# then waits to be killed or to exit with the code it is given on stdin.
_CHILD = r"""
import sys
sys.path.insert(0, sys.argv[1])
from sniper.procutil import process_identity
print("%d %d" % process_identity(), flush=True)
line = sys.stdin.readline()
sys.exit(int(line) if line.strip() else 0)
"""


@pytest.fixture
def child():
    procs = []

    def start():
        p = subprocess.Popen([sys.executable, "-c", _CHILD, _SRC],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             universal_newlines=True)
        procs.append(p)
        pid, created = (int(x) for x in p.stdout.readline().split())
        assert pid == p.pid
        return p, created

    yield start
    for p in procs:
        if p.poll() is None:
            p.kill()
        p.wait(10)
        for stream in (p.stdin, p.stdout):
            stream.close()


# ── Identity ─────────────────────────────────────────────────────────────────
@windows_only
def test_identity_of_the_current_process_is_stable():
    pid, created = procutil.process_identity()
    assert pid == os.getpid()
    assert created > 0
    assert procutil.process_identity() == (pid, created)
    assert procutil.process_identity(os.getpid()) == (pid, created)


@windows_only
def test_identity_of_a_child_matches_what_it_reports_itself(child):
    p, created = child()
    # Read from outside (OpenProcess) and from inside (GetCurrentProcess):
    # the same process, the same creation time.
    assert created > 0
    assert procutil.process_identity(p.pid) == (p.pid, created)
    assert procutil.process_identity(p.pid) != procutil.process_identity()


@windows_only
def test_identity_of_a_pid_nobody_has_is_zero():
    assert procutil.process_identity(0xFFFFFFF0) == (0xFFFFFFF0, 0)


# ── open_for_wait / wait_any / exit_code ─────────────────────────────────────
@windows_only
def test_open_for_wait_refuses_a_wrong_creation_time(child):
    p, created = child()
    for wrong in (created - 1, created + 1, 0):
        assert procutil.open_for_wait(p.pid, wrong) is None
    handle = procutil.open_for_wait(p.pid, created)
    assert handle
    procutil.close(handle)


@windows_only
def test_wait_returns_the_index_of_the_killed_process(child):
    alive, alive_created = child()
    doomed, doomed_created = child()
    h_alive = procutil.open_for_wait(alive.pid, alive_created)
    h_doomed = procutil.open_for_wait(doomed.pid, doomed_created)
    try:
        assert procutil.wait_any([h_alive, h_doomed], 50) is None  # both running
        assert procutil.exit_code(h_doomed) == procutil.STILL_ACTIVE
        doomed.kill()  # TerminateProcess
        assert procutil.wait_any([h_alive, h_doomed], 10000) == 1
        assert procutil.exit_code(h_doomed) == 1  # Popen.kill's exit code
        assert procutil.exit_code(h_alive) == procutil.STILL_ACTIVE
    finally:
        procutil.close(h_alive)
        procutil.close(h_doomed)


@windows_only
def test_exit_code_reads_the_code(child):
    p, created = child()
    handle = procutil.open_for_wait(p.pid, created)
    try:
        p.stdin.write("7\n")
        p.stdin.flush()
        assert procutil.wait_any([handle], 10000) == 0
        assert procutil.exit_code(handle) == 7
    finally:
        procutil.close(handle)


@windows_only
def test_a_dead_pid_gives_none():
    # Not the fixture: it would keep the Popen, and with it a handle that
    # keeps the dead process object alive.
    p = subprocess.Popen([sys.executable, "-c", _CHILD, _SRC], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, universal_newlines=True)
    try:
        pid, created = (int(x) for x in p.stdout.readline().split())
        p.stdin.write("0\n")
        p.stdin.flush()
        p.wait(10)
    finally:
        if p.poll() is None:
            p.kill()
            p.wait(10)
        p.stdin.close()
        p.stdout.close()
    # Drop the last handle to the process object, so the PID is really free
    # (or already reused, which must read as "gone" just the same).
    del p
    gc.collect()

    def gone():
        handle = procutil.open_for_wait(pid, created)
        procutil.close(handle)  # a handle would itself keep the object alive
        return handle is None

    assert wait_until(gone, timeout=5)


@windows_only
def test_a_killed_process_someone_still_holds_signals_at_once(child):
    # The test's Popen keeps a handle, so the dead process object lives on:
    # opening it still works, and the wait returns at once. This is what a
    # guardian sees when SNIper was killed just before it started watching.
    p, created = child()
    p.kill()
    p.wait(10)
    handle = procutil.open_for_wait(p.pid, created)
    assert handle
    try:
        assert procutil.wait_any([handle], 0) == 0
    finally:
        procutil.close(handle)


@windows_only
def test_wait_any_rejects_bad_input():
    with pytest.raises(ValueError):
        procutil.wait_any([], 0)
    with pytest.raises(ValueError):
        procutil.wait_any([1] * 65, 0)
    with pytest.raises(OSError):
        procutil.wait_any([0x12345678], 0)  # not a handle: WAIT_FAILED


@windows_only
def test_close_and_exit_code_accept_none():
    procutil.close(None)
    assert procutil.exit_code(None) is None


@windows_only
def test_every_win32_call_is_fully_bound():
    k = procutil._kernel32
    for name in ("GetCurrentProcess", "OpenProcess", "GetProcessTimes",
                 "WaitForMultipleObjects", "GetExitCodeProcess", "CloseHandle"):
        fn = getattr(k, name)
        assert fn.argtypes is not None, name
        assert fn.restype is not None, name
    # Handles are pointer-sized.
    assert k.OpenProcess.restype is ctypes.c_void_p
    assert k.GetCurrentProcess.restype is ctypes.c_void_p
    assert k.CloseHandle.argtypes == [ctypes.c_void_p]
    # A private DLL object: the shared ctypes.windll.kernel32 is untouched.
    assert k is not ctypes.windll.kernel32


# ── Off Windows ──────────────────────────────────────────────────────────────
def test_off_windows_everything_degrades(monkeypatch):
    monkeypatch.setattr(procutil, "IS_WINDOWS", False)
    assert procutil.process_identity() == (os.getpid(), 0)
    assert procutil.process_identity(1234) == (1234, 0)
    assert procutil.open_for_wait(1234, 5) is None
    with pytest.raises(OSError):
        procutil.wait_any([1], 0)
    assert procutil.exit_code(1) is None
    procutil.close(1)
