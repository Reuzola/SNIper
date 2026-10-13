"""Tests for the shared test infrastructure.

Every later test trusts the fake registry, the sandbox and the real-proxy
guard, so each of their safety promises is checked here: the fake refuses HKLM
writes and wrong-access handles, the recursive delete refuses anything outside
the sandbox, and the sandbox really is redirected and really is removed.
"""
from __future__ import annotations

import time

import pytest

import conftest
import sniper.settings as settings
import sniper.winproxy as winproxy
from fakewinreg import (ABSENT, HKCU, HKLM, IE_KEY, IE_POLICY, KEY_READ,
                        KEY_WRITE, REG_DWORD, REG_SZ, RESTORE_KEY, FakeWinreg)
from helpers import (RegistrySandbox, delete_registry_tree, new_sandbox_path,
                     wait_until)
from sniper.compat import IS_WINDOWS, winreg

windows_only = pytest.mark.skipif(not IS_WINDOWS, reason="needs the Windows registry")


# ── FakeWinreg ───────────────────────────────────────────────────────────────
def test_fake_hklm_is_readable_but_never_writable():
    fake = FakeWinreg()
    fake.set_gpo_locked(True)
    k = fake.OpenKey(HKLM, IE_POLICY)
    assert fake.QueryValueEx(k, "ProxySettingsPerUser") == (0, REG_DWORD)
    with pytest.raises(AssertionError, match="outside HKCU"):
        fake.SetValueEx(k, "X", 0, REG_DWORD, 1)
    with pytest.raises(AssertionError, match="outside HKCU"):
        fake.DeleteValue(k, "ProxySettingsPerUser")
    fake.CloseKey(k)
    for write in (lambda: fake.CreateKey(HKLM, r"Software\X"),
                  lambda: fake.DeleteKey(HKLM, IE_POLICY)):
        with pytest.raises(AssertionError, match="outside HKCU"):
            write()
    with pytest.raises(FileNotFoundError):
        fake.OpenKey(HKLM, r"Software\Missing")
    assert ("OpenKey", "hklm\\" + IE_POLICY.lower()) in fake.calls
    fake.set_gpo_locked(False)
    k = fake.OpenKey(HKLM, IE_POLICY)
    assert fake.QueryValueEx(k, "ProxySettingsPerUser") == (1, REG_DWORD)
    fake.CloseKey(k)
    assert fake.keys == {}  # nothing landed in HKCU
    assert fake.open == 0


def test_fake_enforces_handle_access():
    fake = FakeWinreg()
    fake.put(IE_KEY, "ProxyEnable", 0)
    k = fake.OpenKey(HKCU, IE_KEY)  # KEY_READ by default, as in winreg
    with pytest.raises(AssertionError, match="access"):
        fake.SetValueEx(k, "ProxyEnable", 0, REG_DWORD, 1)
    with pytest.raises(AssertionError, match="access"):
        fake.DeleteValue(k, "ProxyEnable")
    fake.CloseKey(k)
    k = fake.OpenKey(HKCU, IE_KEY, 0, KEY_WRITE)
    with pytest.raises(AssertionError, match="access"):
        fake.QueryValueEx(k, "ProxyEnable")
    fake.SetValueEx(k, "ProxyEnable", 0, REG_DWORD, 1)
    fake.CloseKey(k)
    with pytest.raises(AssertionError, match="closed"):
        fake.QueryValueEx(k, "ProxyEnable")
    k = fake.OpenKey(HKCU, IE_KEY, 0, KEY_READ)
    assert fake.QueryValueEx(k, "ProxyEnable") == (1, REG_DWORD)
    fake.CloseKey(k)


def test_fake_delete_value_and_failures():
    fake = FakeWinreg()
    k = fake.CreateKey(HKCU, RESTORE_KEY)
    fake.SetValueEx(k, "Complete", 0, REG_DWORD, 1)
    fake.DeleteValue(k, "COMPLETE")  # names are case-insensitive
    with pytest.raises(FileNotFoundError):
        fake.DeleteValue(k, "Complete")
    assert ("DeleteValue", RESTORE_KEY.lower(), "COMPLETE") in fake.ops
    fake.fail.add("DeleteValue")
    with pytest.raises(PermissionError):
        fake.DeleteValue(k, "Anything")
    fake.fail.clear()
    # A (function, path) pair fails only that key.
    fake.fail.add(("SetValueEx", IE_KEY.lower()))
    fake.SetValueEx(k, "ProxyEnable", 0, REG_DWORD, 0)
    fake.CloseKey(k)
    k = fake.CreateKey(HKCU, IE_KEY)
    with pytest.raises(PermissionError):
        fake.SetValueEx(k, "ProxyEnable", 0, REG_DWORD, 0)
    fake.CloseKey(k)
    with pytest.raises(AssertionError):  # a DWORD must be an unsigned 32-bit int
        k = fake.CreateKey(HKCU, RESTORE_KEY)
        try:
            fake.SetValueEx(k, "Complete", 0, REG_DWORD, -1)
        finally:
            fake.CloseKey(k)
    assert fake.open == 0


def test_fake_live_and_record_helpers():
    fake = FakeWinreg()
    assert fake.record() is None
    fake.set_live(1, "127.0.0.1:8881", "")
    assert fake.live() == (1, "127.0.0.1:8881", "")
    fake.set_live(0, "", ABSENT)
    assert fake.live() == (0, "", ABSENT)
    assert fake.live()[2] is None and fake.live()[2] != ""
    fake.put(RESTORE_KEY, "AppliedProxyServer", "127.0.0.1:1", REG_SZ)
    fake.put(RESTORE_KEY, "Complete", 1)
    assert fake.record() == {"AppliedProxyServer": "127.0.0.1:1", "Complete": 1}
    assert fake.record(types=True)["Complete"] == (1, REG_DWORD)
    assert fake.calls == []  # helpers are not API calls


def test_fake_reg_fixture(fake_reg):
    assert winproxy.winreg is fake_reg and settings.winreg is fake_reg
    assert winproxy.IS_WINDOWS and settings.IS_WINDOWS
    assert fake_reg.live() == (0, "", ABSENT)
    assert winproxy._proxy_gpo_locked() is False  # read through the fake HKLM
    fake_reg.set_gpo_locked(True)
    assert winproxy._proxy_gpo_locked() is True
    winproxy._refresh()
    assert fake_reg.refresh_calls == [0]


# ── helpers ──────────────────────────────────────────────────────────────────
def test_wait_until_returns_the_truthy_value():
    start = time.monotonic()
    values = iter([0, None, "", "done"])
    assert wait_until(lambda: next(values), timeout=5, interval=0.001) == "done"
    assert time.monotonic() - start < 1


def test_wait_until_times_out_with_a_message():
    with pytest.raises(AssertionError, match="never"):
        wait_until(lambda: False, timeout=0.1, interval=0.01, message="never")


@pytest.mark.parametrize("path", [
    r"Software", r"Software\SNIper", r"Software\Microsoft",
    r"Software\SNIper-pytest-abc",
    r"Software\SNIper-pytest-" + "0" * 31,
    r"Software\SNIper-pytest-" + "g" * 32,
    r"Software\SNIper-pytest-" + "0" * 32 + "x",
    r"\Software\SNIper-pytest-" + "0" * 32,
    r"Software\SNIper-pytest-" + "0" * 32 + "\\",
    "", None,
])
def test_delete_registry_tree_refuses_paths_outside_the_sandbox(path):
    with pytest.raises(ValueError):
        delete_registry_tree(HKCU, path)


def test_new_sandbox_path_is_unique_and_accepted():
    a, b = new_sandbox_path(), new_sandbox_path()
    assert a != b
    RegistrySandbox(a)  # validates the path


# ── Real-registry sandbox (Windows) ──────────────────────────────────────────
@windows_only
@pytest.mark.windows_integration
def test_sandbox_lifecycle_removes_the_whole_tree():
    box = RegistrySandbox()
    try:
        box.create()
        assert box.live() == (0, "", ABSENT)
        box.set_live(1, "127.0.0.1:1", "")
        assert box.live() == (1, "127.0.0.1:1", "")
        deep = box.restore_key + r"\a\b"
        winreg.CloseKey(winreg.CreateKey(winreg.HKEY_CURRENT_USER, deep))
        k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, box.restore_key)
        winreg.SetValueEx(k, "Complete", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(k)
        assert box.record() == {"Complete": 1}
        assert box.exists(deep)
    finally:
        box.destroy()
    assert not box.exists()
    box.destroy()  # already gone: still fine


@windows_only
@pytest.mark.windows_integration
def test_registry_sandbox_fixture_redirects_everything(registry_sandbox):
    box = registry_sandbox
    assert box.root.startswith("Software\\SNIper-pytest-")
    assert winproxy._IE == box.root + r"\Internet Settings"
    assert winproxy._SNIPER_KEY == box.root + r"\SNIper"
    assert winproxy._RESTORE_KEY == box.root + r"\SNIper\ProxyRestore"
    assert settings.SETTINGS_KEY == box.root + r"\SNIper\Settings"
    assert winproxy._proxy_gpo_locked() is False
    assert box.live() == (0, "", ABSENT)
    # A real round trip through winproxy lands in the sandbox only.
    assert winproxy.proxy_enable("127.0.0.1:1") is None
    assert box.live() == (1, "127.0.0.1:1", ABSENT)
    assert box.record()["Complete"] == 1
    assert winproxy.proxy_restore() == "restored"
    assert box.live() == (0, "", ABSENT)
    assert box.record() is None
    assert not box.exists(box.sniper_key)


@windows_only
@pytest.mark.windows_integration
def test_guard_snapshot_tells_absent_from_empty():
    box = RegistrySandbox()
    try:
        box.create()
        before = conftest._read_tree(box.root)
        box.set_live(0, "", "")
        after = conftest._read_tree(box.root)
        assert before != after
        assert "AutoConfigURL" not in before["Internet Settings"]
        assert after["Internet Settings"]["AutoConfigURL"] == ("", winreg.REG_SZ)
    finally:
        box.destroy()
    assert conftest._read_tree(box.root) is None
