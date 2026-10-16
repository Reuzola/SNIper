"""The one test that touches the REAL system proxy. Opt-in only.

It proves that Windows honors the legacy values safe mode writes: with a
safe-mode server running against the real keys, WinHTTP must report SNIper's
script as the user's setup script, next to SNIper's manual proxy with a bypass
list of every host, and its PAC engine must route example.com through SNIper.
Stop must then leave the real values exactly as they were, and Windows' own
view of them too.

Skipped unless SNIPER_ALLOW_REAL_PROXY_TESTS=1, and never run without the
user's consent. The real values are snapshotted first; a finally block writes
the snapshot back if anything differs. This is the only place a test writes the
real registry, and only to put the user's own values back.
"""
from __future__ import annotations

import ctypes
import os

import pytest

import sniper.winproxy as winproxy
from sniper.compat import IS_WINDOWS, winreg
from sniper.server import ProxyServer

pytestmark = [
    pytest.mark.real_system_proxy,
    pytest.mark.windows_integration,
    pytest.mark.skipif(not IS_WINDOWS, reason="needs Windows"),
    pytest.mark.skipif(os.environ.get("SNIPER_ALLOW_REAL_PROXY_TESTS") != "1",
                       reason="touches the REAL system proxy; opt in with "
                              "SNIPER_ALLOW_REAL_PROXY_TESTS=1"),
]

_IE = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_SNIPER = r"Software\SNIper"
_RESTORE = r"Software\SNIper\ProxyRestore"
_RUNONCE = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
_NAMES = ("ProxyEnable", "ProxyServer", "AutoConfigURL", "ProxyOverride")


def _live():
    """{name: (data, type), or None when absent} for the real live values."""
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE)
    try:
        values = {}
        for name in _NAMES:
            try:
                values[name] = winreg.QueryValueEx(k, name)
            except FileNotFoundError:
                values[name] = None
        return values
    finally:
        winreg.CloseKey(k)


def _put_back(snapshot):
    """Write the user's own values back exactly, type included; a value that
    was absent is deleted."""
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE, 0, winreg.KEY_SET_VALUE)
    try:
        for name in _NAMES:
            if snapshot[name] is None:
                try:
                    winreg.DeleteValue(k, name)
                except FileNotFoundError:
                    pass
            else:
                data, kind = snapshot[name]
                winreg.SetValueEx(k, name, 0, kind, data)
    finally:
        winreg.CloseKey(k)
    winproxy._refresh()


def _exists(path):
    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_CURRENT_USER, path))
        return True
    except FileNotFoundError:
        return False


def _sniper_running():
    """True if a SNIper instance holds its single-instance mutex."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_mutex = kernel32.OpenMutexW
    open_mutex.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_wchar_p]
    open_mutex.restype = ctypes.c_void_p
    close = kernel32.CloseHandle
    close.argtypes = [ctypes.c_void_p]
    close.restype = ctypes.c_int
    handle = open_mutex(0x00100000, False, "SNIper_singleton")  # SYNCHRONIZE
    if handle:
        close(handle)
        return True
    return False


def test_windows_honors_the_safe_mode_setup_script():
    from helpers import winhttp_ie_config, winhttp_proxy_for_url

    # Nothing may stand between this test and the real keys, and nothing of
    # SNIper's may already be there to be confused with what the test does.
    assert (winproxy._IE, winproxy._RESTORE_KEY, winproxy._RUNONCE) == \
        (_IE, _RESTORE, _RUNONCE), "winproxy is redirected; refusing to run"
    if _sniper_running():
        pytest.fail("SNIper is running; close it first", pytrace=False)
    if _exists(_RESTORE):
        pytest.fail("a real SNIper restore record exists; launch SNIper once "
                    "to recover it first", pytrace=False)
    if winproxy._proxy_gpo_locked():
        pytest.fail("Group Policy locks the per-user proxy here; this test "
                    "cannot show anything", pytrace=False)

    before = _live()
    windows_before = winhttp_ie_config()
    sniper_key_existed = _exists(_SNIPER)
    print("before:", before, windows_before)
    server = ProxyServer()
    try:
        server.start(0, 2, False)
        url = server.pac_url
        during = _live()
        windows_during = winhttp_ie_config()
        print("during:", during, windows_during)
        assert during["AutoConfigURL"] == (url, winreg.REG_SZ)
        assert during["ProxyEnable"] == (1, winreg.REG_DWORD)
        assert during["ProxyServer"] == (server.addr, winreg.REG_SZ)
        assert during["ProxyOverride"] == ("*", winreg.REG_SZ)
        # Windows took it: SNIper's script is the setup script, and the manual
        # proxy it falls back to bypasses every host.
        assert windows_during["auto_config_url"] == url
        assert windows_during["proxy"] == server.addr
        assert windows_during["proxy_bypass"] == "*"
        # And its PAC engine sends traffic through SNIper.
        result = winhttp_proxy_for_url("https://example.com/",
                                       windows_during["auto_config_url"])
        print("example.com:", result)
        assert result.names_proxy(server.addr)

        server.stop()
        after = _live()
        windows_after = winhttp_ie_config()
        print("after:", after, windows_after)
        assert after == before
        assert windows_after == windows_before
        assert not _exists(_RESTORE)
        assert _exists(_SNIPER) == sniper_key_existed
    finally:
        server.stop()  # idempotent: a no-op if the test got this far
        if _live() != before:
            _put_back(before)
        if not sniper_key_existed and _exists(_SNIPER):
            winproxy._clear_baseline()  # what SNIper's own restore would do
