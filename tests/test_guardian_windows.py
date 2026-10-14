"""End-to-end tests for the guardian, with real processes, on Windows.

The owner is the self-test owner (python -m sniper --selftest-owner): a real
ProxyServer session that applies the proxy to the registry sandbox and starts
a real guardian through the real intermediate. Everything runs against the
sandbox (handed over in SNIPER_REGISTRY_SANDBOX), with notifications off.

A guardian is found by its command line (--guard <pid> <ctime> <session>)
and opened BEFORE the owner is killed, so its exit code can be read: 10
restored, 11 kept, 0 nothing to do. Every process a test starts is killed by
PID afterwards, guardians and intermediates included.
"""
from __future__ import annotations

import gc
import os
import subprocess
import sys
import time

import pytest

import sniper.procutil as procutil
import sniper.winproxy as winproxy
from helpers import ABSENT, wait_until
from sniper.compat import IS_WINDOWS

pytestmark = [pytest.mark.skipif(not IS_WINDOWS, reason="real Windows processes"),
              pytest.mark.windows_integration, pytest.mark.slow,
              pytest.mark.real_guardian]

if IS_WINDOWS:
    from helpers import guard_processes, taskkill

_SRC = os.path.dirname(os.path.dirname(os.path.abspath(winproxy.__file__)))
GENUINE = (0, "", ABSENT)
RESTORE_TIMEOUT = 15
# The graceful case stops on its own after this many seconds. Long enough for
# the (about 1 s) process query to find the guardian first, so its exit code
# can be read; the spec's example is 2 s, which leaves that race to luck.
GRACEFUL_STOP_AFTER = 6


class Run:
    """One end-to-end scenario: its owner, its guardian, and cleanup."""

    def __init__(self, box):
        self.box = box
        self.procs = []         # Popen objects this test started
        self.handles = []       # guardian handles opened for their exit codes
        self.sessions = set()   # session ids whose processes must not survive
        self.env = dict(os.environ)
        self.env.update(box.env)
        self.env["SNIPER_GUARD_NOTIFY"] = "0"
        self.env["PYTHONPATH"] = _SRC

    def start_owner(self, mode, *extra):
        p = subprocess.Popen([sys.executable, "-m", "sniper", "--selftest-owner", mode]
                             + list(extra), env=self.env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.procs.append(p)

        def ready():
            if p.poll() is not None:
                raise AssertionError("the owner exited early (%s): %s"
                                     % (p.returncode, p.stderr.read()))
            return (self.box.selftest() or {}).get("Ready") == 1

        wait_until(ready, timeout=30)
        info = self.box.selftest()
        self.sessions.add(info["SessionId"])
        assert info["OwnerPid"] == p.pid, "the owner is not the process started"
        return p, info

    def guardian(self, session_id, wait_for_intermediate=False):
        """Find the session's guardian and open it for its exit code."""
        self.sessions.add(session_id)
        found = wait_until(lambda: guard_processes(session_id), timeout=30,
                           message="no guardian appeared for %s" % session_id)
        assert len(found) == 1, found
        if wait_for_intermediate:
            wait_until(lambda: not guard_processes(session_id, "--spawn-guard"),
                       timeout=30, message="the intermediate never exited")
        pid = found[0]
        handle = procutil.open_for_wait(pid, procutil.process_identity(pid)[1])
        assert handle, "the guardian %d was gone before it could be opened" % pid
        self.handles.append(handle)
        return pid, handle

    def exit_code(self, handle, timeout=RESTORE_TIMEOUT):
        assert procutil.wait_any([handle], int(timeout * 1000)) == 0, \
            "the guardian did not exit within %s s" % timeout
        return procutil.exit_code(handle)

    def assert_watching(self, handle, footprint):
        """The guardian waits while its owner lives: it is still running a
        moment later, and the footprint and the record are untouched."""
        assert procutil.wait_any([handle], 500) is None, "the guardian left early"
        assert self.box.live() == footprint
        assert self.box.record() is not None

    def cleanup(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
            p.wait(30)
            p.stderr.close()
        for session_id in self.sessions:
            for mode in ("--spawn-guard", "--guard"):
                for pid in guard_processes(session_id, mode):
                    taskkill(pid)
        for handle in self.handles:
            procutil.wait_any([handle], 10000)
            procutil.close(handle)
        for session_id in self.sessions:
            assert not guard_processes(session_id), "a guardian survived the test"


@pytest.fixture
def run(registry_sandbox):
    r = Run(registry_sandbox)
    try:
        yield r
    finally:
        r.cleanup()


def pac_url(port):
    return "http://127.0.0.1:%d/sniper-" % port


# ── 1./2. Hard kill ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("mode", ["safe", "compat"])
def test_hard_kill_restores_within_seconds(run, registry_sandbox, mode):
    box = registry_sandbox
    owner, info = run.start_owner(mode)
    if mode == "safe":
        assert box.live()[:2] == (0, "") and box.live()[2].startswith(pac_url(info["Port"]))
    else:
        assert box.live() == (1, "127.0.0.1:%d" % info["Port"], ABSENT)
    assert box.record()["SessionId"] == info["SessionId"]
    _, handle = run.guardian(info["SessionId"])
    run.assert_watching(handle, box.live())
    killed = time.perf_counter()
    owner.kill()  # TerminateProcess: no code of the owner's runs any more
    assert run.exit_code(handle) == 10
    print("%s: restored %.3f s after the kill" % (mode, time.perf_counter() - killed))
    assert box.live() == GENUINE
    assert box.record() is None
    assert not box.exists(box.sniper_key)


# ── 3. Graceful stop ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("mode", ["safe", "compat"])
def test_graceful_stop_lets_the_guardian_leave_quietly(run, registry_sandbox, mode):
    box = registry_sandbox
    owner, info = run.start_owner(mode, "--stop-after", str(GRACEFUL_STOP_AFTER))
    _, handle = run.guardian(info["SessionId"])
    assert owner.poll() is None, "the owner stopped before the guardian was found"
    run.assert_watching(handle, box.live())
    assert owner.wait(GRACEFUL_STOP_AFTER + 30) == 0
    assert box.selftest().get("Stopped") == 1
    assert run.exit_code(handle, timeout=10) == 0
    assert box.live() == GENUINE
    assert box.record() is None


# ── 4. The user took control ─────────────────────────────────────────────────
@pytest.mark.parametrize("mode", ["safe", "compat"])
def test_a_user_change_is_kept(run, registry_sandbox, mode):
    box = registry_sandbox
    owner, info = run.start_owner(mode)
    e, s, a = box.live()
    if mode == "safe":
        user = (e, s, "http://user/own.pac")       # their own setup script
    else:
        user = (e, "user-proxy:3128", a)           # their own proxy server
    box.set_live(*user)
    _, handle = run.guardian(info["SessionId"])
    run.assert_watching(handle, user)
    owner.kill()
    assert run.exit_code(handle) == 11
    assert box.live() == user
    assert box.record() is None


# ── 5. The owner was already dead ────────────────────────────────────────────
def dead_process(keep_handle):
    """The identity of a process that ran and was killed. With keep_handle,
    this test still holds a handle, so the dead process object lingers (the
    guardian can open it, and its wait returns at once); without, nothing
    does, and it is gone for good, as a killed SNIper normally is."""
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        identity = procutil.process_identity(child.pid)
        assert identity[1] > 0
    finally:
        child.kill()
        child.wait(10)
    if keep_handle:
        return identity, child
    del child
    gc.collect()

    def gone():
        handle = procutil.open_for_wait(*identity)
        procutil.close(handle)
        return handle is None

    wait_until(gone, timeout=10)
    return identity, None


@pytest.mark.parametrize("keep_handle", [False, True], ids=["gone", "lingering"])
def test_owner_already_dead_when_the_guardian_starts(run, registry_sandbox, monkeypatch,
                                                     keep_handle):
    box = registry_sandbox
    identity, _held = dead_process(keep_handle)
    sid = "a1b2c3d4e5f60718"
    url = "http://127.0.0.1:1/sniper-%s.pac" % sid
    monkeypatch.setattr(procutil, "process_identity", lambda pid=None: identity)
    winproxy.proxy_enable("127.0.0.1:1", pac_url=url, session_id=sid)
    monkeypatch.undo()  # only the record was meant to name the dead child
    assert box.record()["OwnerPid"] == identity[0]
    assert box.live() == (0, "", url)
    run.sessions.add(sid)
    guard = subprocess.run([sys.executable, "-m", "sniper", "--guard", str(identity[0]),
                            str(identity[1]), sid], env=run.env, timeout=60,
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    assert guard.returncode == 10, guard.stderr
    assert box.live() == GENUINE
    assert box.record() is None


# ── 6. A newer session ───────────────────────────────────────────────────────
def test_a_newer_session_sends_the_old_guardian_away(run, registry_sandbox):
    box = registry_sandbox
    owner, info = run.start_owner("safe")
    _, handle = run.guardian(info["SessionId"])
    # Another apply (here: this test process) takes the record over.
    newer = "fedcba9876543210"
    url = box.live()[2]
    winproxy.proxy_enable("127.0.0.1:%d" % info["Port"], pac_url=url, session_id=newer)
    assert run.exit_code(handle, timeout=10) == 0
    record = box.record()
    assert record["SessionId"] == newer
    live = box.live()
    owner.kill()
    owner.wait(30)
    # The old guardian is gone, so nothing touches the newer session's record.
    assert not guard_processes(info["SessionId"])
    assert box.record() == record
    assert box.live() == live


def test_a_dead_owner_never_restores_a_newer_sessions_record(run, registry_sandbox,
                                                            monkeypatch):
    # The owner died, and by the time its guardian acts the record already
    # belongs to a newer session: the guardian must leave it alone
    # ("not-ours", 13). This is the race the session check in proxy_restore
    # exists for; the wait loop's own check can't see it, because the owner's
    # death wins.
    box = registry_sandbox
    dead, _ = dead_process(keep_handle=False)
    old, newer = "1111111111111111", "2222222222222222"
    url = "http://127.0.0.1:1/sniper-%s.pac" % newer
    winproxy.proxy_enable("127.0.0.1:1", pac_url=url, session_id=newer)
    live, record = box.live(), box.record()
    run.sessions.update({old, newer})
    guard = subprocess.run([sys.executable, "-m", "sniper", "--guard", str(dead[0]),
                            str(dead[1]), old], env=run.env, timeout=60,
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    assert guard.returncode == 13, guard.stderr
    assert (box.live(), box.record()) == (live, record)


# ── Start / Stop from a live owner (this process) ────────────────────────────
@pytest.fixture
def live_owner(registry_sandbox, monkeypatch):
    """A ProxyServer in this process, whose real guardians use the sandbox."""
    from sniper.server import ProxyServer
    for name, value in registry_sandbox.env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("SNIPER_GUARD_NOTIFY", "0")
    server = ProxyServer()
    try:
        yield server
    finally:
        server.stop()


def test_stop_and_start_cycles_leave_no_guardian_behind(run, registry_sandbox, live_owner):
    # Its owner keeps running after every Stop, as the app does: each
    # guardian must leave because its record went, not because its owner
    # died, or guardians would pile up over Start/Stop cycles.
    box = registry_sandbox
    for compat in (False, True, False):
        live_owner.start(0, 2, False, compat=compat)
        sid = live_owner.session_id
        _, handle = run.guardian(sid)
        run.assert_watching(handle, box.live())
        live_owner.stop()
        assert run.exit_code(handle, timeout=10) == 0
        assert box.live() == GENUINE
        assert not guard_processes(sid)


def test_cancelled_sign_out_hands_over_to_a_new_guardian(run, registry_sandbox,
                                                         live_owner):
    box = registry_sandbox
    live_owner.start(0, 2, False)
    first = live_owner.session_id
    _, first_handle = run.guardian(first)
    live_owner.session_ending()        # WM_QUERYENDSESSION: restored
    assert run.exit_code(first_handle, timeout=10) == 0
    assert box.live() == GENUINE
    live_owner.session_end_cancelled()  # WM_ENDSESSION(FALSE): re-applied
    second = live_owner.session_id
    assert second != first
    _, second_handle = run.guardian(second)
    run.assert_watching(second_handle, box.live())
    live_owner.stop()
    assert run.exit_code(second_handle, timeout=10) == 0
    assert box.live() == GENUINE


# ── 7. Tree kill ─────────────────────────────────────────────────────────────
def test_the_guardian_survives_a_tree_kill(run, registry_sandbox):
    # The intermediate has exited, so the guardian has no parent in the
    # owner's tree: taskkill /T can't reach it. (A tree kill while the
    # intermediate still lives can take the guardian down; launch recovery
    # and safe mode cover that first second or two.)
    box = registry_sandbox
    owner, info = run.start_owner("compat")
    guard_pid, handle = run.guardian(info["SessionId"], wait_for_intermediate=True)
    run.assert_watching(handle, box.live())
    result = taskkill(owner.pid, tree=True)
    assert result.returncode == 0, result.stderr
    owner.wait(30)
    assert run.exit_code(handle) == 10
    assert box.live() == GENUINE
    assert box.record() is None


# ── 8. Guardian killed first ─────────────────────────────────────────────────
def test_with_the_guardian_killed_first_launch_recovery_restores(run, registry_sandbox):
    # The layering: without a guardian nothing restores at the kill, and the
    # next launch's recovery does.
    box = registry_sandbox
    owner, info = run.start_owner("compat")
    guard_pid, handle = run.guardian(info["SessionId"])
    assert taskkill(guard_pid).returncode == 0
    assert run.exit_code(handle) == 1  # taskkill /F's exit code
    footprint, record = box.live(), box.record()
    owner.kill()
    owner.wait(30)
    assert box.live() == footprint     # stranded: nobody is left to restore
    assert box.record() == record
    assert winproxy.recover_orphaned_proxy() == "restored"
    assert box.live() == GENUINE
    assert box.record() is None
