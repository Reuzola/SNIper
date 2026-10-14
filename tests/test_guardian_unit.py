"""Unit tests for sniper.guardian, with fakes, on any OS.

- Launching: the command and environment (frozen vs. from source), the
  creation flags, the retry without job breakaway, the reaper thread.
- The owner side and the intermediate: what they launch, and when they
  refuse to.
- The guardian's decision logic, with an injected waiter and record reader:
  when it restores, when it leaves quietly, how outcomes map to exit codes,
  when it notifies, and what happens when something breaks.
- The self-test owner's refusal, dispatch, and the entry points, including
  that the guard path never imports tkinter or the app.

The Windows section at the end drives the real Win32 waiter against the
registry sandbox and a child process.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import textwrap
import threading
import types

import pytest

import sniper.guardian as guardian
import sniper.procutil as procutil
import sniper.winproxy as winproxy
from helpers import wait_until
from sniper.compat import IS_WINDOWS

_SRC = os.path.dirname(os.path.dirname(os.path.abspath(guardian.__file__)))
SID = "0123456789abcdef"
PID, CTIME = 4242, 133_700_000_000_000_000
ARGS = [str(PID), str(CTIME), SID]
DETACHED, NEW_GROUP, BREAKAWAY = 0x8, 0x200, 0x01000000


# ── Launching ────────────────────────────────────────────────────────────────
@pytest.fixture
def popen(monkeypatch):
    """guardian's subprocess.Popen as a recorder; .fail makes the first N
    calls raise OSError (e.g. a job that forbids breakaway)."""
    rec = types.SimpleNamespace(calls=[], fail=0, procs=[])

    class FakeProc:
        def __init__(self, cmd, **kwargs):
            rec.calls.append((cmd, kwargs))
            if len(rec.calls) <= rec.fail:
                raise PermissionError(5, "Access is denied")
            self.waited = threading.Event()
            self.timeout = None
            rec.procs.append(self)

        def wait(self, timeout=None):
            self.timeout = timeout
            self.waited.set()
            return 0

    monkeypatch.setattr(guardian, "subprocess", types.SimpleNamespace(
        Popen=FakeProc, DEVNULL=subprocess.DEVNULL))
    return rec


def test_source_command_and_environment(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setenv("PYTHONPATH", "already-there")
    monkeypatch.setenv("SNIPER_TEST_MARKER", "inherited")
    assert guardian._base_cmd() == [sys.executable, "-m", "sniper"]
    env = guardian._child_env()
    assert env["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    assert env["PYTHONPATH"] == _SRC + os.pathsep + "already-there"
    assert os.path.isdir(os.path.join(env["PYTHONPATH"].split(os.pathsep)[0], "sniper"))
    assert env["SNIPER_TEST_MARKER"] == "inherited"  # e.g. the sandbox variable
    assert "PYINSTALLER_RESET_ENVIRONMENT" not in os.environ  # a copy


def test_source_environment_without_a_pythonpath(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    assert guardian._child_env()["PYTHONPATH"] == _SRC


def test_frozen_command_and_environment(monkeypatch):
    exe = r"C:\Apps\SNIper_x64.exe"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", exe)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    assert guardian._base_cmd() == [exe]
    env = guardian._child_env()
    assert env["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    assert "PYTHONPATH" not in env  # the EXE carries its own package


def test_launch_is_detached_and_breaks_away(popen, monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    assert guardian._launch_detached(["--guard", 1, 2, SID]) is True
    (cmd, kwargs), = popen.calls
    assert cmd == [sys.executable, "-m", "sniper", "--guard", "1", "2", SID]
    assert kwargs["creationflags"] == DETACHED | NEW_GROUP | BREAKAWAY
    assert kwargs["stdin"] == kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
    assert kwargs["close_fds"] is True
    assert kwargs["env"]["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    # Reaped from a daemon thread, with a timeout.
    assert popen.procs[0].waited.wait(5)
    assert popen.procs[0].timeout == 120


def test_launch_retries_without_breakaway(popen):
    popen.fail = 1
    assert guardian._launch_detached(["--guard"]) is True
    flags = [kwargs["creationflags"] for _, kwargs in popen.calls]
    assert flags == [DETACHED | NEW_GROUP | BREAKAWAY, DETACHED | NEW_GROUP]


def test_launch_that_fails_twice_reports_false(popen):
    popen.fail = 2
    assert guardian._launch_detached(["--guard"]) is False
    assert len(popen.calls) == 2


# ── Owner side and intermediate ──────────────────────────────────────────────
@pytest.fixture
def launches(monkeypatch):
    calls = []
    result = types.SimpleNamespace(value=True, calls=calls)
    monkeypatch.setattr(guardian, "_launch_detached",
                        lambda args: calls.append(list(args)) or result.value)
    return result


def test_spawn_guardian_launches_the_intermediate(launches, monkeypatch):
    monkeypatch.setattr(guardian, "IS_WINDOWS", True)
    monkeypatch.setattr(procutil, "process_identity", lambda pid=None: (PID, CTIME))
    assert guardian.spawn_guardian(SID) is True
    assert launches.calls == [["--spawn-guard", PID, CTIME, SID]]
    launches.value = False
    assert guardian.spawn_guardian(SID) is False


@pytest.mark.parametrize("sid", [None, "", "0123", SID.upper(), SID + "0", "g" * 16])
def test_spawn_guardian_refuses_a_bad_session(launches, monkeypatch, sid):
    monkeypatch.setattr(guardian, "IS_WINDOWS", True)
    assert guardian.spawn_guardian(sid) is False
    assert launches.calls == []


def test_spawn_guardian_refuses_an_unknown_creation_time(launches, monkeypatch):
    # A guardian could not tell this process from one that later gets its
    # PID, and would undo a live SNIper's proxy.
    monkeypatch.setattr(guardian, "IS_WINDOWS", True)
    monkeypatch.setattr(procutil, "process_identity", lambda pid=None: (PID, 0))
    assert guardian.spawn_guardian(SID) is False
    assert launches.calls == []


def test_spawn_guardian_never_raises(monkeypatch):
    monkeypatch.setattr(guardian, "IS_WINDOWS", True)
    monkeypatch.setattr(procutil, "process_identity", lambda pid=None: (PID, CTIME))

    def boom(args):
        raise RuntimeError("exploded")
    monkeypatch.setattr(guardian, "_launch_detached", boom)
    assert guardian.spawn_guardian(SID) is False


def test_spawn_guardian_off_windows(launches, monkeypatch):
    monkeypatch.setattr(guardian, "IS_WINDOWS", False)
    assert guardian.spawn_guardian(SID) is False
    assert launches.calls == []


def test_intermediate_launches_the_guardian_and_returns(launches):
    assert guardian.run_spawn_guard(ARGS) == 0
    assert launches.calls == [["--guard", str(PID), str(CTIME), SID]]
    launches.value = False
    assert guardian.run_spawn_guard(ARGS) == 3


BAD_ARGS = [
    [], ARGS[:2], ARGS + ["x"],
    ["0", str(CTIME), SID],                      # no PID 0
    [str(2 ** 32), str(CTIME), SID],             # beyond a DWORD
    [str(PID), "0", SID],                        # unknown creation time
    [str(PID), str(2 ** 64), SID],               # beyond a FILETIME
    ["-1", str(CTIME), SID], ["x", str(CTIME), SID], [" 1", str(CTIME), SID],
    [str(PID), "1.5", SID], ["\u0661", str(CTIME), SID],  # an Arabic-Indic 1
    [str(PID), str(CTIME), SID.upper()], [str(PID), str(CTIME), SID[:-1]],
    [str(PID), str(CTIME), SID + "\n"], [str(PID), str(CTIME), "zz"],
]


@pytest.mark.parametrize("args", BAD_ARGS, ids=repr)
def test_bad_arguments_are_refused(launches, args):
    assert guardian.run_spawn_guard(args) == 2
    assert guardian.run_guardian(args, waiter=ExplodingWaiter(),
                                 read_session=_unused) == 2
    assert launches.calls == []


# ── The guardian's logic ─────────────────────────────────────────────────────
class ExplodingWaiter:
    def __getattr__(self, name):
        raise AssertionError("the waiter must not be used")


def _unused():
    raise AssertionError("the record must not be read")


class FakeWaiter:
    """Plays back a script of wake-ups: "owner", "record", None (a polling
    timeout), or an exception to raise from wait()."""

    def __init__(self, script=(), owner_alive=True, arms=()):
        self.script = list(script)
        self.owner_alive = owner_alive
        self.arm_results = list(arms)
        self.opened = None
        self.arms = 0
        self.waits = []      # the armed flag of each wait
        self.closed = []

    def open_owner(self, pid, created):
        self.opened = (pid, created)
        return "owner-handle" if self.owner_alive else None

    def arm(self):
        self.arms += 1
        return self.arm_results.pop(0) if self.arm_results else True

    def wait(self, owner, armed):
        assert owner == "owner-handle"
        self.waits.append(armed)
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def close(self, owner):
        self.closed.append(owner)


class Sessions:
    """A record reader returning the given values in turn (the last one
    repeats)."""

    def __init__(self, *values):
        self.values = list(values)
        self.reads = 0

    def __call__(self):
        self.reads += 1
        return self.values.pop(0) if len(self.values) > 1 else self.values[0]


@pytest.fixture
def restores(monkeypatch):
    rec = types.SimpleNamespace(calls=[], result="restored", exc=None)

    def restore(session_id=None):
        rec.calls.append(session_id)
        if rec.exc is not None:
            raise rec.exc
        return rec.result

    monkeypatch.setattr(winproxy, "proxy_restore", restore)
    return rec


@pytest.fixture
def notices(monkeypatch):
    calls = []
    monkeypatch.setattr(guardian, "notify_restored", lambda: calls.append(1) or True)
    monkeypatch.delenv("SNIPER_GUARD_NOTIFY", raising=False)
    return calls


def test_owner_dead_at_start_restores_at_once(restores, notices):
    waiter = FakeWaiter(owner_alive=False)
    assert guardian.run_guardian(ARGS, waiter=waiter, read_session=_unused) == 10
    assert waiter.opened == (PID, CTIME)
    assert restores.calls == [SID]  # its own session only
    assert waiter.arms == 0 and waiter.waits == []


def test_owner_dies_while_watched(restores, notices):
    waiter = FakeWaiter(["owner"])
    assert guardian.run_guardian(ARGS, waiter=waiter, read_session=Sessions(SID)) == 10
    assert restores.calls == [SID]
    assert waiter.waits == [True]          # waited on owner + notification
    assert waiter.closed == ["owner-handle"]


def test_record_gone_leaves_quietly(restores, notices):
    waiter = FakeWaiter(["record"])
    sessions = Sessions(SID, None)   # a clean Stop cleared the record
    assert guardian.run_guardian(ARGS, waiter=waiter, read_session=sessions) == 0
    assert restores.calls == [] and notices == []
    assert waiter.closed == ["owner-handle"]


def test_record_gone_before_watching_leaves_quietly(restores, notices):
    waiter = FakeWaiter([])
    assert guardian.run_guardian(ARGS, waiter=waiter, read_session=Sessions(None)) == 0
    assert waiter.waits == [] and restores.calls == []


def test_newer_session_leaves_quietly(restores, notices):
    waiter = FakeWaiter(["record"])
    sessions = Sessions(SID, "fedcba9876543210")
    assert guardian.run_guardian(ARGS, waiter=waiter, read_session=sessions) == 0
    assert restores.calls == []


def test_unrelated_changes_rearm_and_keep_watching(restores, notices):
    # E.g. "Remember settings" writing under the same key.
    waiter = FakeWaiter(["record", "record", "owner"])
    sessions = Sessions(SID)
    assert guardian.run_guardian(ARGS, waiter=waiter, read_session=sessions) == 10
    assert waiter.arms == 3            # the first arm, then once per change
    assert sessions.reads == 3         # checked after every (re-)arm
    assert waiter.waits == [True, True, True]


def test_without_notifications_it_polls(restores, notices):
    waiter = FakeWaiter([None, None, "owner"], arms=[False])
    sessions = Sessions(SID)
    assert guardian.run_guardian(ARGS, waiter=waiter, read_session=sessions) == 10
    assert waiter.waits == [False, False, False]
    assert sessions.reads == 3         # the record checked at every poll


def test_polling_sees_the_record_go(restores, notices):
    waiter = FakeWaiter([None, None], arms=[False])
    assert guardian.run_guardian(ARGS, waiter=waiter,
                                 read_session=Sessions(SID, SID, None)) == 0
    assert restores.calls == []


def test_a_broken_notification_falls_back_to_polling(restores, notices):
    waiter = FakeWaiter([OSError("WAIT_FAILED"), None, "owner"])
    assert guardian.run_guardian(ARGS, waiter=waiter, read_session=Sessions(SID)) == 10
    assert waiter.waits == [True, False, False]


def test_a_rearm_that_fails_falls_back_to_polling(restores, notices):
    waiter = FakeWaiter(["record", None, "owner"], arms=[True, False])
    assert guardian.run_guardian(ARGS, waiter=waiter, read_session=Sessions(SID)) == 10
    assert waiter.waits == [True, False, False]


@pytest.mark.parametrize("failure", ["wait", "read"])
def test_an_exception_still_attempts_a_final_restore(restores, notices, failure):
    if failure == "wait":
        # Even the plain wait on the owner fails, while polling.
        waiter = FakeWaiter([OSError("WAIT_FAILED")], arms=[False])
        sessions = Sessions(SID)
    else:
        waiter = FakeWaiter([])

        def sessions():
            raise RuntimeError("registry exploded")
    assert guardian.run_guardian(ARGS, waiter=waiter, read_session=sessions) == 3
    assert restores.calls == [SID]
    assert notices == []
    assert waiter.closed == ["owner-handle"]


def test_a_restore_that_raises_is_exit_3(restores, notices):
    restores.exc = RuntimeError("restore exploded")
    assert guardian.run_guardian(ARGS, waiter=FakeWaiter(owner_alive=False),
                                 read_session=_unused) == 3
    assert restores.calls == [SID, SID]  # the attempt, and the final one


@pytest.mark.parametrize("outcome, code", [
    ("restored", 10), ("kept", 11), ("already", 12), ("not-ours", 13), (None, 0),
    ("something new", 3),
])
def test_outcomes_map_to_exit_codes(restores, notices, outcome, code):
    restores.result = outcome
    assert guardian.run_guardian(ARGS, waiter=FakeWaiter(owner_alive=False),
                                 read_session=_unused) == code
    assert notices == ([1] if outcome == "restored" else [])


def test_notification_can_be_turned_off(restores, notices, monkeypatch):
    monkeypatch.setenv("SNIPER_GUARD_NOTIFY", "0")
    assert guardian.run_guardian(ARGS, waiter=FakeWaiter(owner_alive=False),
                                 read_session=_unused) == 10
    assert notices == []
    monkeypatch.setenv("SNIPER_GUARD_NOTIFY", "1")
    guardian.run_guardian(ARGS, waiter=FakeWaiter(owner_alive=False),
                          read_session=_unused)
    assert notices == [1]


def test_exit_codes_are_distinct():
    codes = [guardian.EXIT_NOTHING, guardian.EXIT_BAD_ARGS, guardian.EXIT_ERROR,
             guardian.EXIT_RESTORED, guardian.EXIT_KEPT, guardian.EXIT_ALREADY,
             guardian.EXIT_NOT_OURS]
    assert codes == [0, 2, 3, 10, 11, 12, 13]


# ── Self-test owner and dispatch ─────────────────────────────────────────────
class NoRegistry:
    def __getattr__(self, name):
        raise AssertionError("the registry must not be touched")


def test_selftest_owner_refuses_without_a_sandbox(monkeypatch):
    monkeypatch.setattr(winproxy, "_SANDBOXED", False)
    monkeypatch.setattr(guardian, "winreg", NoRegistry())
    monkeypatch.setattr(winproxy, "winreg", NoRegistry())
    assert guardian.run_selftest_owner(["safe"]) == 3
    assert guardian.run_selftest_owner(["compat", "--stop-after", "1"]) == 3


@pytest.mark.parametrize("args", [[], ["fast"], ["safe", "--stop-after"],
                                  ["safe", "--stop-after", "x"], ["safe", "-1"],
                                  ["safe", "--stop-after", "-1"], ["safe", "extra"]],
                         ids=repr)
def test_selftest_owner_bad_arguments(monkeypatch, args):
    monkeypatch.setattr(winproxy, "_SANDBOXED", True)
    monkeypatch.setattr(guardian, "winreg", NoRegistry())
    assert guardian.run_selftest_owner(args) == 2


def test_dispatch_routes_each_mode(monkeypatch):
    seen = []
    for name, mode in (("run_guardian", "--guard"), ("run_spawn_guard", "--spawn-guard"),
                       ("run_selftest_owner", "--selftest-owner")):
        monkeypatch.setattr(guardian, name,
                            lambda args, name=name: seen.append((name, args)) or 7)
        assert guardian.dispatch([mode, "a", "b"]) == 7
    assert seen == [("run_guardian", ["a", "b"]), ("run_spawn_guard", ["a", "b"]),
                    ("run_selftest_owner", ["a", "b"])]
    assert guardian.MODES == ("--guard", "--spawn-guard", "--selftest-owner")


@pytest.mark.parametrize("argv", [[], ["--gaurd", *ARGS], ["guard", *ARGS], ["", *ARGS]],
                         ids=repr)
def test_dispatch_unknown_mode_is_bad_arguments(argv):
    assert guardian.dispatch(argv) == 2


def test_dispatch_never_raises(monkeypatch):
    def boom(args):
        raise RuntimeError("exploded")
    monkeypatch.setattr(guardian, "run_guardian", boom)
    assert guardian.dispatch(["--guard", *ARGS]) == 3


# ── Imports and entry points (subprocesses) ──────────────────────────────────
FORBIDDEN = ("tkinter", "sniper.ui", "sniper.app", "sniper.proxy", "sniper.dns",
             "sniper.server")


def _python(code, *args, env=None):
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code), _SRC] + list(args),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, timeout=60, env=env)


def test_guard_path_imports_without_tkinter():
    proc = _python("""
        import sys
        sys.modules["tkinter"] = None
        sys.path.insert(0, sys.argv[1])
        import sniper.guardian
        assert sniper.guardian.dispatch(["--guard", "x"]) == 2
        loaded = [m for m in %r if sys.modules.get(m) is not None]
        assert loaded == [], loaded
    """ % (FORBIDDEN,))
    assert proc.returncode == 0, proc.stderr


@pytest.mark.parametrize("entry", ["module", "script"])
@pytest.mark.parametrize("argv, code", [
    (["--guard", "1", "2", "zz"], 2),
    (["--spawn-guard", "1"], 2),
    (["--selftest-owner", "safe"], 3),   # no sandbox: refused
])
def test_entry_points_dispatch_before_the_app(entry, argv, code):
    # run as python -m sniper / src\run_sniper.py would be, with tkinter
    # unavailable: the mode runs, and neither the app nor Tk is imported.
    proc = _python("""
        import runpy, sys
        sys.modules["tkinter"] = None
        src = sys.argv[1]
        sys.path.insert(0, src)
        entry, argv = sys.argv[2], sys.argv[3:]
        sys.argv = ["sniper"] + argv
        try:
            if entry == "module":
                runpy.run_module("sniper", run_name="__main__", alter_sys=True)
            else:
                runpy.run_path(src + "/run_sniper.py", run_name="__main__")
        except SystemExit as e:
            code = e.code
        else:
            code = "no exit"
        loaded = [m for m in %r if sys.modules.get(m) is not None]
        assert loaded == [], loaded
        print(code)
    """ % (FORBIDDEN,), entry, *argv, env=_env_without_sandbox())
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == str(code)


def test_python_dash_m_sniper_guard_exits_with_its_code():
    env = _env_without_sandbox()
    env["PYTHONPATH"] = _SRC
    proc = subprocess.run([sys.executable, "-m", "sniper", "--guard", "1", "2", "zz"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, timeout=60, env=env)
    assert proc.returncode == 2
    assert proc.stdout == proc.stderr == ""  # the guard path never prints


def _env_without_sandbox():
    env = dict(os.environ)
    env.pop("SNIPER_REGISTRY_SANDBOX", None)
    return env


# ── The notification (its contents; no real icon is shown) ──────────────────
def test_notify_off_windows(monkeypatch):
    monkeypatch.setattr(guardian, "IS_WINDOWS", False)
    assert guardian.notify_restored() is False


@pytest.mark.skipif(not IS_WINDOWS, reason="builds a real (hidden) Win32 window")
def test_notification_contents_and_cleanup(monkeypatch):
    from sniper import tray
    seen = []

    def shell_notify(message, nid):
        seen.append({"message": message, "flags": nid.uFlags, "hwnd": nid.hWnd,
                     "icon": nid.hIcon, "tip": nid.szTip, "title": nid.szInfoTitle,
                     "info": nid.szInfo, "info_flags": nid.dwInfoFlags,
                     "size": nid.cbSize, "callback": nid.uCallbackMessage})
        return True

    monkeypatch.setattr(guardian, "_shell_notify", shell_notify)
    assert guardian.notify_restored(seconds=0.2) is True
    add, delete = seen
    assert (add["message"], delete["message"]) == (0, 2)  # NIM_ADD, then NIM_DELETE
    assert add["flags"] == 0x1 | 0x2 | 0x4 | 0x10         # MESSAGE|ICON|TIP|INFO
    assert add["title"] == "SNIper" and add["tip"] == "SNIper"
    assert add["info"] == ("SNIper closed unexpectedly. Your internet settings "
                           "were restored automatically.")
    assert add["info_flags"] == 0x1                        # NIIF_INFO
    assert add["icon"] and add["icon"] == tray._tray_hicon()
    assert add["size"] == ctypes.sizeof(tray._NOTIFYICONDATAW)
    assert add["callback"] == tray._WM_TRAY_CB
    assert add["hwnd"] and delete["hwnd"] == add["hwnd"]
    from helpers import is_window
    assert not is_window(add["hwnd"])  # the hidden window is gone again
    # And the class is free again: a second notification works.
    assert guardian.notify_restored(seconds=0) is True


@pytest.mark.skipif(not IS_WINDOWS, reason="builds a real (hidden) Win32 window")
def test_notification_failures_are_silent(monkeypatch):
    seen = []
    monkeypatch.setattr(guardian, "_shell_notify",
                        lambda message, nid: seen.append(message) or False)
    assert guardian.notify_restored(seconds=0) is False
    assert seen == [0]  # nothing to delete when the add failed

    def boom(message, nid):
        raise OSError("shell32 exploded")
    monkeypatch.setattr(guardian, "_shell_notify", boom)
    assert guardian.notify_restored(seconds=0) is False


# ── The real Win32 waiter ────────────────────────────────────────────────────
@pytest.fixture
def sleeper():
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    yield p
    if p.poll() is None:
        p.kill()
    p.wait(10)


@pytest.mark.skipif(not IS_WINDOWS, reason="Win32 handles and registry notifications")
@pytest.mark.windows_integration
def test_win32_waiter_sees_the_record_change_and_the_owner_die(registry_sandbox, sleeper):
    winproxy.proxy_enable("127.0.0.1:8881", session_id=SID)
    waiter = guardian._Win32Waiter()
    owner = waiter.open_owner(*procutil.process_identity(sleeper.pid))
    assert owner
    try:
        assert waiter.arm() is True
        result = {}
        t = threading.Thread(target=lambda: result.setdefault("woke",
                             waiter.wait(owner, True)), daemon=True)
        t.start()
        t.join(0.3)
        assert t.is_alive()  # nothing changed yet, and the owner lives
        winproxy.proxy_restore()  # the record goes: a change in the subtree
        t.join(10)
        assert result["woke"] == "record"
        assert winproxy.current_session_id() is None
        # Re-armed on a key that is gone now (the restore removed it): no
        # notifications, so the guardian would poll; the owner still wakes it.
        waiter.arm()
        sleeper.kill()
        assert wait_until(lambda: waiter.wait(owner, False) == "owner", timeout=10)
    finally:
        waiter.close(owner)


@pytest.mark.skipif(not IS_WINDOWS, reason="Win32 registry notifications")
@pytest.mark.windows_integration
def test_win32_waiter_cannot_arm_without_the_key(registry_sandbox):
    waiter = guardian._Win32Waiter()
    try:
        assert not registry_sandbox.exists(registry_sandbox.sniper_key)
        assert waiter.arm() is False
    finally:
        waiter.close(None)


@pytest.mark.skipif(not IS_WINDOWS, reason="Win32 bindings")
def test_guardian_win32_calls_are_fully_bound():
    for fn in (guardian._kernel32.CreateEventW, guardian._kernel32.CloseHandle,
               guardian._advapi32.RegNotifyChangeKeyValue):
        assert fn.argtypes is not None and fn.restype is not None
    assert guardian._advapi32.RegNotifyChangeKeyValue.argtypes[0] is ctypes.c_void_p
    assert guardian._kernel32.CreateEventW.restype is ctypes.c_void_p
    assert guardian._kernel32 is not ctypes.windll.kernel32
