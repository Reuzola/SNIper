"""Windows system-proxy registry management.

Saves the prior per-user proxy settings BEFORE any write so an interrupt
mid-change can still be restored, temporarily clears any active PAC script
(AutoConfigURL), and warns instead of failing silently when Group Policy
locks per-user proxy settings. Logic unchanged from the embedded original;
the platform flag and winreg now come from sniper.compat.
"""
from __future__ import annotations

import ctypes

from sniper.compat import IS_WINDOWS, winreg

_IE        = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_IE_POLICY = r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"


def _proxy_gpo_locked():
    """True if Group Policy disables per-user proxy settings.

    When HKLM ...\\Internet Settings\\ProxySettingsPerUser is 0, Windows
    ignores the per-user (HKCU) proxy values this program writes — the write
    succeeds but has no effect. Detecting it lets us warn the user instead of
    failing silently on a managed/corporate machine.
    """
    if not IS_WINDOWS:
        return False
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _IE_POLICY)
        try:
            val = winreg.QueryValueEx(k, "ProxySettingsPerUser")[0]
        finally:
            winreg.CloseKey(k)
        return val == 0
    except OSError:
        return False


def _refresh():
    if not IS_WINDOWS:
        return
    try:
        w = ctypes.windll.wininet
        w.InternetSetOptionW(0, 39, 0, 0); w.InternetSetOptionW(0, 37, 0, 0)
    except Exception:
        pass


def proxy_enable(addr):
    if not IS_WINDOWS:
        return None, None, None
    # Captured before the try: if a registry write fails partway through, the
    # values read so far are still returned so the caller can restore — never
    # silently drop the restore data and leave the proxy half-changed.
    old_e, old_s, old_a = None, None, None
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE, 0,
                           winreg.KEY_READ | winreg.KEY_WRITE)
        try:
            try:
                old_e = winreg.QueryValueEx(k, "ProxyEnable")[0]
            except FileNotFoundError:
                old_e = 0
            try:
                old_s = winreg.QueryValueEx(k, "ProxyServer")[0]
            except FileNotFoundError:
                old_s = ""
            # AutoConfigURL is a PAC script; Windows evaluates it BEFORE the
            # static ProxyServer, so a PAC returning DIRECT would bypass us.
            # None means the value did not exist (leave it absent on restore).
            try:
                old_a = winreg.QueryValueEx(k, "AutoConfigURL")[0]
            except FileNotFoundError:
                old_a = None
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, addr)
            # Temporarily disable any PAC script so it cannot bypass us.
            if old_a:
                winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ, "")
        finally:
            winreg.CloseKey(k)
        _refresh()
    except Exception:
        pass
    return old_e, old_s, old_a


def proxy_restore(old_e, old_s, old_a=None):
    if not IS_WINDOWS:
        return
    if old_e is None:
        return
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE, 0, winreg.KEY_WRITE)
        try:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, int(old_e))
            winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, old_s or "")
            # Restore the PAC script if one was present. None means it never
            # existed, so leave it absent rather than creating an empty value.
            if old_a is not None:
                winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ, old_a)
        finally:
            winreg.CloseKey(k)
        _refresh()
    except Exception:
        pass
