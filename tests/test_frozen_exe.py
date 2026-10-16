"""Checks against the built EXE, where onefile behavior can differ from source.

Runs only when SNIPER_TEST_EXE names a built SNIper_<arch>.exe (see
packaging\\build_exe.bat); skipped otherwise. Everything runs in the registry
sandbox, handed to the EXE in SNIPER_REGISTRY_SANDBOX, with notifications off.

A onefile EXE runs as two processes with the same command line: a launcher
(the bootloader, which unpacks to %TEMP%\\_MEI*) and its child, the Python
process that really is SNIper. So the self-test owner's OwnerPid is the
child, not the process the test started, and a guardian is a launcher and a
child too. The child is what Task Manager ends with "End task" on the
window's process; the launcher is what a tree kill starts from.

_MEI hygiene: every launcher that exits normally deletes its own _MEI
directory, and a guardian unpacks to its own (PYINSTALLER_RESET_ENVIRONMENT),
so it never holds on to SNIper's. A launcher that is itself terminated (the
tree kill) can't delete its directory: that is PyInstaller's onefile design,
not SNIper's, so exactly that one is expected, and then removed by the test.
Another PyInstaller app started during the run would show up there too.
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import time

import pytest

import sniper.procutil as procutil
from helpers import ABSENT, wait_until
from sniper.compat import IS_WINDOWS

EXE = os.environ.get("SNIPER_TEST_EXE")

pytestmark = [
    pytest.mark.skipif(not IS_WINDOWS, reason="a Windows EXE"),
    pytest.mark.skipif(not (EXE and os.path.isfile(EXE)),
                       reason="set SNIPER_TEST_EXE to a built SNIper_<arch>.exe"),
    pytest.mark.windows_integration, pytest.mark.slow, pytest.mark.real_guardian,
]

if IS_WINDOWS:
    from helpers import taskkill

GENUINE = (0, "", ABSENT)
NET = {"SNIperRestoreProxyEnable", "SNIperRestoreProxyServer"}
RESTORE_TIMEOUT = 15
GRACEFUL_STOP_AFTER = 6   # as in test_guardian_windows.py: time to find the guard
_CREATE_NO_WINDOW = 0x08000000
_MEI_NAME = re.compile(r"_MEI\d+")


# ── Processes of the EXE ─────────────────────────────────────────────────────
def _powershell(command):
    out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                          "[Console]::OutputEncoding = [Text.Encoding]::UTF8; " + command],
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, timeout=60, creationflags=_CREATE_NO_WINDOW)
    if out.returncode != 0:
        raise OSError("PowerShell failed: %r" % (out.stderr,))
    text = out.stdout.decode("utf-8", "replace").strip().lstrip("﻿")
    found = json.loads(text) if text else []
    return [found] if isinstance(found, dict) else found


def exe_processes():
    """[(pid, parent pid, command line)] of every process of the EXE under test."""
    name = os.path.basename(EXE)
    assert re.fullmatch(r"[\w.-]+", name), name   # nothing a WQL string could misread
    found = _powershell("Get-CimInstance Win32_Process -Filter \"Name = '%s'\" | "
                        "Select ProcessId,ParentProcessId,CommandLine | ConvertTo-Json" % name)
    return [(p["ProcessId"], p["ParentProcessId"], p.get("CommandLine") or "") for p in found]


def pair(mode, session_id, processes=None):
    """(launcher pid, child pid) running `mode <pid> <ctime> session_id`, or
    None until both exist (the child's parent being the launcher)."""
    rx = re.compile(r"(?:^|\s)%s\s+\d+\s+\d+\s+%s(?:\s|$)" % (re.escape(mode), session_id))
    found = [(pid, ppid) for pid, ppid, cmd in (processes or exe_processes()) if rx.search(cmd)]
    pids = {pid for pid, _ in found}
    launchers = [pid for pid, ppid in found if ppid not in pids]
    children = [pid for pid, ppid in found if ppid in pids]
    if len(found) == 2 and len(launchers) == 1 and len(children) == 1:
        return launchers[0], children[0]
    assert len(found) <= 2, found
    return None


def parent_of(pid):
    for p, ppid, _ in exe_processes():
        if p == pid:
            return ppid
    return None


def memory(pids):
    """{pid: (working set, private bytes)} in bytes."""
    found = _powershell("Get-Process -Id %s | Select Id,WorkingSet64,PrivateMemorySize64 | "
                        "ConvertTo-Json" % ",".join(str(p) for p in pids))
    return {p["Id"]: (p["WorkingSet64"], p["PrivateMemorySize64"]) for p in found}


def mei_dir_of(pid):
    """The _MEI directory a frozen child runs from: where its python DLL was
    loaded from."""
    found = _powershell("(Get-Process -Id %d).Modules | Where-Object { $_.ModuleName -like "
                        "'python3*.dll' } | Select-Object -First 1 FileName | ConvertTo-Json"
                        % pid)
    assert found, "no python DLL in process %d" % pid
    directory = os.path.dirname(found[0]["FileName"])
    assert _MEI_NAME.fullmatch(os.path.basename(directory)), directory
    return os.path.normcase(directory)


def mei_dirs():
    """Every %TEMP%\\_MEI* directory (TMP and TEMP, as GetTempPath may use either)."""
    roots = {os.environ.get(name) for name in ("TMP", "TEMP")} - {None}
    return {os.path.normcase(d) for root in roots
            for d in glob.glob(os.path.join(root, "_MEI*")) if os.path.isdir(d)}


# ── _MEI bookkeeping for the whole module ────────────────────────────────────
class MeiWatch:
    def __init__(self):
        self.before = mei_dirs()
        self.expected = set()   # the _MEI dirs of launchers a test terminated


@pytest.fixture(scope="module")
def mei():
    watch = MeiWatch()
    yield watch
    # Remove what the terminated launchers had to leave behind: exactly those
    # directories, each a _MEI dir of a launcher of this run that is dead.
    for directory in watch.expected:
        if os.path.isdir(directory) and directory not in watch.before:
            shutil.rmtree(directory, ignore_errors=True)


# ── One scenario ─────────────────────────────────────────────────────────────
class FrozenRun:
    """The EXE as owner, its guardian, and cleanup by PID."""

    def __init__(self, box):
        self.box = box
        self.owners = []        # Popen objects of the launchers this test started
        self.pids = set()       # every pid of ours that must be gone at the end
        self.handles = []
        self.sessions = set()
        self.env = dict(os.environ)
        self.env.update(box.env)
        self.env["SNIPER_GUARD_NOTIFY"] = "0"

    def start_owner(self, mode, *extra):
        p = subprocess.Popen([EXE, "--selftest-owner", mode] + list(extra), env=self.env,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        self.owners.append(p)

        def ready():
            if p.poll() is not None:
                raise AssertionError("the owner exited early (%s)" % p.returncode)
            return (self.box.selftest() or {}).get("Ready") == 1

        wait_until(ready, timeout=60)
        info = self.box.selftest()
        self.sessions.add(info["SessionId"])
        self.pids.add(info["OwnerPid"])
        # The real owner is the launcher's child.
        assert info["OwnerPid"] != p.pid
        assert parent_of(info["OwnerPid"]) == p.pid
        return p, info

    def guardian(self, session_id, wait_for_intermediate=False):
        """The session's guardian (launcher, child), opened for exit codes."""
        found = wait_until(lambda: pair("--guard", session_id), timeout=30,
                           message="no guardian appeared for %s" % session_id)
        if wait_for_intermediate:
            wait_until(lambda: not [1 for _, _, cmd in exe_processes()
                                    if "--spawn-guard" in cmd and session_id in cmd],
                       timeout=30, message="the intermediate never exited")
        handles = []
        for pid in found:
            self.pids.add(pid)
            handle = procutil.open_for_wait(pid, procutil.process_identity(pid)[1])
            assert handle, "guardian process %d was gone before it could be opened" % pid
            self.handles.append(handle)
            handles.append(handle)
        return found, handles

    def exit_codes(self, handles, timeout=RESTORE_TIMEOUT):
        codes = []
        for handle in handles:
            assert procutil.wait_any([handle], int(timeout * 1000)) == 0, \
                "a guardian process did not exit within %s s" % timeout
            codes.append(procutil.exit_code(handle))
        return codes

    def assert_watching(self, handles, footprint):
        assert procutil.wait_any(handles, 500) is None, "the guardian left early"
        assert self.box.live() == footprint
        assert self.box.record() is not None

    def cleanup(self):
        for p in self.owners:
            if p.poll() is None:
                p.kill()
            p.wait(30)
        for pid, _, cmd in exe_processes():
            if pid in self.pids or any(s in cmd for s in self.sessions):
                taskkill(pid)
        for handle in self.handles:
            procutil.wait_any([handle], 10000)
            procutil.close(handle)
        wait_until(lambda: not [pid for pid, _, cmd in exe_processes()
                                if pid in self.pids or any(s in cmd for s in self.sessions)],
                   timeout=30, message="a process of this test survived it")


@pytest.fixture
def frun(registry_sandbox):
    r = FrozenRun(registry_sandbox)
    try:
        yield r
    finally:
        r.cleanup()


def expected_live(mode, info):
    if mode == "compat":
        return (1, "127.0.0.1:%d" % info["Port"], ABSENT)
    return None


def check_applied(box, mode, info):
    if mode == "compat":
        assert box.live() == expected_live(mode, info)
        net = box.runonce()
        assert set(net) == NET
        assert all(('"HKCU\\%s"' % box.ie) in c for c in net.values())
    else:
        e, s, a = box.live()
        assert (e, s) == (0, "") and a.startswith("http://127.0.0.1:%d/sniper-" % info["Port"])
        assert not box.runonce()


def check_restored(box):
    assert box.live() == GENUINE
    assert box.record() is None
    assert not box.runonce()


# ── 1. Dispatch ──────────────────────────────────────────────────────────────
def _run_exe(args, env=None):
    started = time.monotonic()
    proc = subprocess.run([EXE] + args, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    return proc.returncode, time.monotonic() - started


@pytest.mark.parametrize("args", [["--guard", "1", "2", "zz"], ["--guard"],
                                  ["--spawn-guard", "x"], ["--selftest-owner", "neither"]])
def test_bad_helper_arguments_exit_2(mei, args, registry_sandbox):
    env = dict(os.environ)
    env.update(registry_sandbox.env)
    code, seconds = _run_exe(args, env)
    print("%s -> %s in %.2f s" % (args, code, seconds))
    assert code == 2


@pytest.mark.parametrize("sandbox", [None, r"Software\SNIper", r"Software\SNIper-pytest-abc"],
                         ids=["unset", "real-key", "short-id"])
def test_the_selftest_owner_refuses_without_a_sandbox(mei, sandbox):
    env = dict(os.environ)
    env.pop("SNIPER_REGISTRY_SANDBOX", None)
    if sandbox is not None:
        env["SNIPER_REGISTRY_SANDBOX"] = sandbox
    code, seconds = _run_exe(["--selftest-owner", "safe"], env)
    print("--selftest-owner safe with %r -> %s in %.2f s" % (sandbox, code, seconds))
    assert code == 3   # and the session's real-proxy guard proves nothing was touched


# ── 2. The app process is killed (Task Manager "End task", taskkill /F) ──────
@pytest.mark.parametrize("mode", ["safe", "compat"])
def test_killing_the_app_process_restores(mei, frun, registry_sandbox, mode):
    box = registry_sandbox
    owner, info = frun.start_owner(mode)
    check_applied(box, mode, info)
    guard, handles = frun.guardian(info["SessionId"])
    frun.assert_watching(handles, box.live())
    usage = memory(guard)
    print("%s guardian memory (working set, private), MB: launcher %.1f / %.1f, "
          "child %.1f / %.1f" % ((mode,) + tuple(n / 2 ** 20 for pid in guard
                                                 for n in usage[pid])))
    killed = time.perf_counter()
    result = taskkill(info["OwnerPid"])
    assert result.returncode == 0, result.stderr
    assert frun.exit_codes(handles) == [10, 10]
    print("%s: restored %.3f s after the kill" % (mode, time.perf_counter() - killed))
    check_restored(box)
    owner.wait(30)   # the launcher follows its child


# ── Graceful stop ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("mode", ["safe", "compat"])
def test_a_graceful_stop_lets_the_guardian_leave_quietly(mei, frun, registry_sandbox, mode):
    box = registry_sandbox
    owner, info = frun.start_owner(mode, "--stop-after", str(GRACEFUL_STOP_AFTER))
    _, handles = frun.guardian(info["SessionId"])
    assert owner.poll() is None, "the owner stopped before the guardian was found"
    frun.assert_watching(handles, box.live())
    assert owner.wait(GRACEFUL_STOP_AFTER + 30) == 0
    assert box.selftest().get("Stopped") == 1
    assert frun.exit_codes(handles, timeout=10) == [0, 0]
    check_restored(box)


# ── The user took control ────────────────────────────────────────────────────
def test_a_user_change_is_kept_and_the_net_still_goes(mei, frun, registry_sandbox):
    box = registry_sandbox
    owner, info = frun.start_owner("compat")
    e, s, a = box.live()
    user = (e, "user-proxy:3128", a)
    box.set_live(*user)
    _, handles = frun.guardian(info["SessionId"])
    frun.assert_watching(handles, user)
    assert taskkill(info["OwnerPid"]).returncode == 0
    assert frun.exit_codes(handles) == [11, 11]
    assert box.live() == user
    assert box.record() is None
    assert not box.runonce()   # a blind restore must not undo the user's change


# ── 3. Tree kill of the launcher ─────────────────────────────────────────────
@pytest.mark.parametrize("mode", ["safe", "compat"])
def test_the_guardian_survives_a_tree_kill_of_the_launcher(mei, frun, registry_sandbox, mode):
    box = registry_sandbox
    owner, info = frun.start_owner(mode)
    check_applied(box, mode, info)
    guard, handles = frun.guardian(info["SessionId"], wait_for_intermediate=True)
    frun.assert_watching(handles, box.live())
    # The launcher about to be terminated can't delete its _MEI directory.
    owner_dir = mei_dir_of(info["OwnerPid"])
    guard_dir = mei_dir_of(guard[1])
    assert owner_dir != guard_dir   # the guardian unpacked to its own
    mei.expected.add(owner_dir)
    result = taskkill(owner.pid, tree=True)
    assert result.returncode == 0, result.stderr
    owner.wait(30)
    assert frun.exit_codes(handles) == [10, 10]
    check_restored(box)
    wait_until(lambda: not os.path.isdir(guard_dir), timeout=15,
               message="the guardian's launcher left its _MEI directory behind")


# ── 4. _MEI hygiene (runs last in this module) ───────────────────────────────
def test_no_mei_directory_is_left_behind(mei):
    # Every launcher of this module exited normally except the tree-killed
    # ones, whose directories are expected (and removed afterwards).
    assert not [pid for pid, _, cmd in exe_processes()
                if "--selftest-owner" in cmd or "--guard" in cmd or "--spawn-guard" in cmd], \
        "a helper process of the EXE is still running"

    def settled():
        return mei_dirs() - mei.before == mei.expected

    try:
        wait_until(settled, timeout=15)
    except AssertionError:
        pytest.fail("new _MEI directories: %r, expected only: %r"
                    % (sorted(mei_dirs() - mei.before), sorted(mei.expected)))
