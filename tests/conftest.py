"""Put ``src/`` on sys.path so ``import sniper.*`` works in the test run, and
provide the registry fixtures every test shares.

The rule behind all of them: a test must never touch the developer's real
proxy settings, because a test that breaks the proxy is exactly the bug SNIper
is guarding against.

- fake_reg: an in-memory registry for unit tests, on any OS.
- registry_sandbox: a throwaway real-registry tree for Windows integration
  tests, deleted afterwards.
- real_proxy_guard: snapshots the real proxy state when the session starts and
  fails the run if anything differs at the end. It only ever reads.
- guardian_spawns (autouse): in-process tests never start a real guardian
  process unless marked real_guardian.
"""
from __future__ import annotations

import contextlib
import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
_SRC = os.path.normpath(_SRC)
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import pytest  # noqa: E402

import sniper.server as server  # noqa: E402
import sniper.settings as settings  # noqa: E402
import sniper.winproxy as winproxy  # noqa: E402
from sniper.compat import IS_WINDOWS, winreg  # noqa: E402

from fakewinreg import ABSENT, FakeWinreg  # noqa: E402
from helpers import RegistrySandbox, sandbox_keys  # noqa: E402


# ── Unit tests: in-memory registry ───────────────────────────────────────────
@pytest.fixture
def fake_reg(monkeypatch):
    """A FakeWinreg in place of the registry for winproxy and settings, as if
    on Windows: live proxy off and empty with no AutoConfigURL, Group Policy
    not locking it, and winproxy._refresh replaced by a recorder
    (fake_reg.refresh_calls holds len(fake_reg.ops) at each call, so a test
    can check the refresh came after the writes).

    winproxy's cross-process state lock is replaced by a recorder too, so no
    real mutex is involved: fake_reg.lock_spans holds (len(calls) at entry,
    len(calls) at exit) per hold, fake_reg.locked tells whether it is held
    right now, and taking it while it is held fails the test (winproxy must
    never re-enter it)."""
    fake = FakeWinreg()
    fake.refresh_calls = []
    fake.lock_spans = []
    fake.locked = False
    fake.set_live(0, "", ABSENT)
    for module in (winproxy, settings):
        monkeypatch.setattr(module, "winreg", fake)
        monkeypatch.setattr(module, "IS_WINDOWS", True)
    monkeypatch.setattr(winproxy, "_refresh",
                        lambda: fake.refresh_calls.append(len(fake.ops)))

    @contextlib.contextmanager
    def state_lock():
        assert not fake.locked, "the state lock was re-entered"
        fake.locked = True
        entered = len(fake.calls)
        try:
            yield True
        finally:
            fake.locked = False
            fake.lock_spans.append((entered, len(fake.calls)))

    monkeypatch.setattr(winproxy, "_state_lock", state_lock)
    yield fake
    assert fake.open == 0, "a registry key was left open"


# ── Windows integration tests: real-registry sandbox ─────────────────────────
@pytest.fixture
def registry_sandbox(monkeypatch):
    """Redirect every key SNIper uses to HKCU\\Software\\SNIper-pytest-<hex>.

    winproxy's _refresh becomes a no-op (it would make every WinINet client
    reload the real settings) and the Group Policy check reports "not locked"
    so the result doesn't depend on the machine. winproxy's state mutex is the
    sandbox's own, so a real SNIper never contends with the test, and winproxy
    reports itself sandboxed exactly as in a subprocess started with box.env.
    The whole tree is deleted afterwards, also when the test fails.
    """
    if not IS_WINDOWS:
        pytest.skip("needs the Windows registry")
    box = RegistrySandbox()
    try:
        box.create()
        monkeypatch.setattr(winproxy, "_IE", box.ie)
        monkeypatch.setattr(winproxy, "_SNIPER_KEY", box.sniper_key)
        monkeypatch.setattr(winproxy, "_RESTORE_KEY", box.restore_key)
        monkeypatch.setattr(winproxy, "_STATE_MUTEX_NAME", box.mutex_name)
        monkeypatch.setattr(winproxy, "_SANDBOXED", True)
        monkeypatch.setattr(winproxy, "_SANDBOX_ROOT", box.root)
        monkeypatch.setattr(settings, "SETTINGS_KEY", box.settings_key)
        monkeypatch.setattr(winproxy, "_refresh", lambda: None)
        monkeypatch.setattr(winproxy, "_proxy_gpo_locked", lambda: False)
        # server.py imported the GPO check by name for its warning line.
        monkeypatch.setattr(server, "_proxy_gpo_locked", lambda: False)
        yield box
    finally:
        box.destroy()


# ── No real guardian processes from in-process tests ─────────────────────────
class GuardianSpawns:
    """Stands in for sniper.server.spawn_guardian: records each session id
    it was asked to guard (calls) and answers result."""

    def __init__(self):
        self.calls = []
        self.result = True

    def __call__(self, session_id):
        self.calls.append(session_id)
        return self.result


@pytest.fixture(autouse=True)
def guardian_spawns(request, monkeypatch):
    """A ProxyServer started in a test process never starts a real guardian
    process: spawn_guardian is a GuardianSpawns recorder, unless the test is
    marked real_guardian (then the fixture's value is None)."""
    if request.node.get_closest_marker("real_guardian") is not None:
        yield None
        return
    spawns = GuardianSpawns()
    monkeypatch.setattr(server, "spawn_guardian", spawns)
    yield spawns


# ── Session guard: the real proxy must be exactly as we found it ─────────────
_REAL_IE = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_REAL_SNIPER = r"Software\SNIper"
_REAL_RUNONCE = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"


def _read_tree(path):
    """{subpath: {value name: (data, type)}} for path and everything below it,
    or None if path doesn't exist. Read-only."""
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
    except FileNotFoundError:
        return None
    try:
        values, children = {}, []
        while True:
            try:
                name, data, kind = winreg.EnumValue(k, len(values))
            except OSError:
                break
            values[name] = (data, kind)
        while True:
            try:
                children.append(winreg.EnumKey(k, len(children)))
            except OSError:
                break
    finally:
        winreg.CloseKey(k)
    tree = {"": values}
    for child in children:
        sub = _read_tree(path + "\\" + child) or {}
        for subpath, vals in sub.items():
            tree[child + ("\\" + subpath if subpath else "")] = vals
    return tree


def _real_snapshot():
    ie = (_read_tree(_REAL_IE) or {}).get("", {})
    runonce = (_read_tree(_REAL_RUNONCE) or {}).get("", {})
    return {
        # Absent and empty differ: a missing value is recorded as "<absent>".
        "live": {name: ie.get(name, "<absent>")
                 for name in ("ProxyEnable", "ProxyServer", "AutoConfigURL")},
        # The whole SNIper tree: the ProxyRestore record and the user's saved
        # settings alike.
        "sniper": _read_tree(_REAL_SNIPER),
        "runonce": {name: value for name, value in runonce.items()
                    if name.lower().startswith("sniper")},
    }


@pytest.fixture(scope="session", autouse=True)
def real_proxy_guard():
    """Fail the run if the real proxy settings, SNIper's real registry tree or
    its RunOnce values changed, or a sandbox key was left behind. Never
    writes; if it fires, the snapshots show what to put back by hand."""
    if not IS_WINDOWS:
        yield
        return
    before = _real_snapshot()
    sandboxes_before = sandbox_keys()
    yield
    after = _real_snapshot()
    leftovers = sorted(sandbox_keys() - sandboxes_before)
    if after != before or leftovers:
        pytest.fail(
            "THE TEST RUN CHANGED THE REAL REGISTRY.\n"
            "before: %r\nafter:  %r\nleft-over sandbox keys: %r"
            % (before, after, leftovers), pytrace=False)
