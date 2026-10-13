"""Shared test helpers: polling with a deadline, the real-registry sandbox, and
the few Win32 calls tests make themselves.

Nothing here may touch the developer's real proxy settings. The only registry
writes go to a throwaway HKCU\\Software\\SNIper-pytest-<32 hex> tree, and the
recursive delete refuses any other path, so a bug in a test can never wipe a
real key.
"""
from __future__ import annotations

import ctypes
import re
import time
import uuid
from collections import namedtuple

from sniper.compat import IS_WINDOWS, winreg

# Same "absent value" convention as fakewinreg.ABSENT and winproxy._read_live.
ABSENT = None

SANDBOX_PREFIX = r"Software\SNIper-pytest-"
_SANDBOX_RX = re.compile(r"^Software\\SNIper-pytest-[0-9a-f]{32}(\\[^\\]+)*$",
                         re.IGNORECASE)


def wait_until(predicate, timeout=10.0, interval=0.05, message=None):
    """Poll predicate until it returns something truthy and return that value.

    Raises AssertionError when timeout seconds pass first. Tests use this
    instead of a fixed sleep, so they are as fast as the code allows and fail
    with a clear message instead of hanging or flaking.
    """
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(
                message or "condition not met within %.1f s: %r" % (timeout, predicate))
        time.sleep(interval)


def new_sandbox_path():
    return SANDBOX_PREFIX + uuid.uuid4().hex


def _check_sandbox_path(path):
    if not _SANDBOX_RX.match(path or ""):
        raise ValueError("refusing to touch a registry path outside the test "
                         "sandbox: %r" % (path,))


def delete_registry_tree(root, path):
    """Delete path and everything below it (winreg.DeleteKey only removes a key
    without subkeys). A missing key is fine. Only sandbox paths are accepted."""
    _check_sandbox_path(path)
    try:
        k = winreg.OpenKey(root, path)
    except FileNotFoundError:
        return
    try:
        children = []
        while True:
            try:
                children.append(winreg.EnumKey(k, len(children)))
            except OSError:
                break
    finally:
        winreg.CloseKey(k)
    for child in children:
        delete_registry_tree(root, path + "\\" + child)
    try:
        winreg.DeleteKey(root, path)
    except FileNotFoundError:
        pass


def sandbox_keys():
    """Names of every Software\\SNIper-pytest-* key currently in HKCU."""
    if not IS_WINDOWS:
        return set()
    found = set()
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software")
    try:
        i = 0
        while True:
            try:
                name = winreg.EnumKey(k, i)
            except OSError:
                break
            if name.lower().startswith("sniper-pytest-"):
                found.add(name)
            i += 1
    finally:
        winreg.CloseKey(k)
    return found


class RegistrySandbox:
    """A throwaway HKCU tree laid out like the keys SNIper uses.

    The registry_sandbox fixture points winproxy and settings at it; tests use
    live(), set_live() and record() just like on the fake registry.
    """

    def __init__(self, root=None):
        self.root = root or new_sandbox_path()
        _check_sandbox_path(self.root)
        self.ie = self.root + r"\Internet Settings"
        self.sniper_key = self.root + r"\SNIper"
        self.restore_key = self.sniper_key + r"\ProxyRestore"
        self.settings_key = self.sniper_key + r"\Settings"

    def create(self):
        winreg.CloseKey(winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.root))
        self.set_live(0, "", ABSENT)

    def destroy(self):
        delete_registry_tree(winreg.HKEY_CURRENT_USER, self.root)

    def exists(self, path=None):
        try:
            winreg.CloseKey(winreg.OpenKey(winreg.HKEY_CURRENT_USER, path or self.root))
            return True
        except FileNotFoundError:
            return False

    def set_live(self, enable=0, server="", pac=ABSENT):
        k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.ie)
        try:
            for name, data, kind in (("ProxyEnable", enable, winreg.REG_DWORD),
                                     ("ProxyServer", server, winreg.REG_SZ),
                                     ("AutoConfigURL", pac, winreg.REG_SZ)):
                if data is ABSENT:
                    try:
                        winreg.DeleteValue(k, name)
                    except FileNotFoundError:
                        pass
                else:
                    winreg.SetValueEx(k, name, 0, kind, data)
        finally:
            winreg.CloseKey(k)

    def _values(self, path):
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
        except FileNotFoundError:
            return None
        try:
            out = {}
            while True:
                try:
                    name, data, _ = winreg.EnumValue(k, len(out))
                except OSError:
                    return out
                out[name] = data
        finally:
            winreg.CloseKey(k)

    def live(self):
        vals = self._values(self.ie) or {}
        return (vals.get("ProxyEnable", ABSENT), vals.get("ProxyServer", ABSENT),
                vals.get("AutoConfigURL", ABSENT))

    def record(self):
        return self._values(self.restore_key)


# ── Win32 helpers for tests ──────────────────────────────────────────────────
# Private DLL handles, so the argtypes bound here never leak into the
# process-wide ctypes.windll objects the code under test configures itself.
if IS_WINDOWS:
    from ctypes import wintypes

    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT,
                                     ctypes.c_size_t, ctypes.c_ssize_t]
    _user32.SendMessageW.restype = ctypes.c_ssize_t
    _user32.IsWindow.argtypes = [wintypes.HWND]
    _user32.IsWindow.restype = wintypes.BOOL
    _user32.IsWindowVisible.argtypes = [wintypes.HWND]
    _user32.IsWindowVisible.restype = wintypes.BOOL
    _user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    _user32.GetAncestor.restype = wintypes.HWND
    _user32.GetDesktopWindow.argtypes = []
    _user32.GetDesktopWindow.restype = wintypes.HWND
    # 64-bit Python only has the "Ptr" export; 32-bit only the plain one.
    _get_window_long = getattr(_user32, "GetWindowLongPtrW", None) or _user32.GetWindowLongW
    _get_window_long.argtypes = [wintypes.HWND, ctypes.c_int]
    _get_window_long.restype = ctypes.c_ssize_t
    _user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND,
                                                 ctypes.POINTER(wintypes.DWORD)]
    _user32.GetWindowThreadProcessId.restype = wintypes.DWORD

    GA_PARENT = 1
    GWL_EXSTYLE = -20
    WS_EX_TOOLWINDOW = 0x00000080

    _kernel32.GetProcessShutdownParameters.argtypes = [
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    _kernel32.GetProcessShutdownParameters.restype = wintypes.BOOL
    _kernel32.SetProcessShutdownParameters.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.SetProcessShutdownParameters.restype = wintypes.BOOL

    def send_message(hwnd, msg, wparam=0, lparam=0):
        """SendMessageW: returns only after the window procedure has run."""
        return _user32.SendMessageW(hwnd, msg, wparam, lparam)

    def is_window(hwnd):
        return bool(_user32.IsWindow(hwnd))

    def is_window_visible(hwnd):
        return bool(_user32.IsWindowVisible(hwnd))

    def is_top_level(hwnd):
        """True for a real top-level window (parent is the desktop); False for
        a child or a message-only (HWND_MESSAGE) window."""
        return _user32.GetAncestor(hwnd, GA_PARENT) == _user32.GetDesktopWindow()

    def window_ex_style(hwnd):
        return _get_window_long(hwnd, GWL_EXSTYLE)

    def window_thread_id(hwnd):
        return _user32.GetWindowThreadProcessId(hwnd, None)

    def get_shutdown_parameters():
        level, flags = wintypes.DWORD(), wintypes.DWORD()
        if not _kernel32.GetProcessShutdownParameters(ctypes.byref(level),
                                                      ctypes.byref(flags)):
            raise ctypes.WinError(ctypes.get_last_error())
        return level.value, flags.value

    def set_shutdown_parameters(level, flags):
        if not _kernel32.SetProcessShutdownParameters(level, flags):
            raise ctypes.WinError(ctypes.get_last_error())

    # ── WinHTTP: what Windows itself makes of a proxy configuration ─────────
    # Read-only queries. WinHttpGetProxyForUrl is handed the script URL
    # explicitly, so it never consults the user's settings at all.
    WINHTTP_ACCESS_TYPE_NO_PROXY = 1
    WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3
    WINHTTP_AUTOPROXY_CONFIG_URL = 0x2
    WINHTTP_AUTOPROXY_RUN_INPROCESS = 0x00010000
    ERROR_WINHTTP_BAD_AUTO_PROXY_SCRIPT = 12166
    ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT = 12167

    class _AutoProxyOptions(ctypes.Structure):
        _fields_ = [("dwFlags", wintypes.DWORD),
                    ("dwAutoDetectFlags", wintypes.DWORD),
                    ("lpszAutoConfigUrl", wintypes.LPCWSTR),
                    ("lpvReserved", ctypes.c_void_p),
                    ("dwReserved", wintypes.DWORD),
                    ("fAutoLogonIfChallenged", wintypes.BOOL)]

    # The strings below are allocated by WinHTTP and freed with GlobalFree,
    # so they are read as raw pointers.
    class _ProxyInfo(ctypes.Structure):
        _fields_ = [("dwAccessType", wintypes.DWORD),
                    ("lpszProxy", ctypes.c_void_p),
                    ("lpszProxyBypass", ctypes.c_void_p)]

    class _IEProxyConfig(ctypes.Structure):
        _fields_ = [("fAutoDetect", wintypes.BOOL),
                    ("lpszAutoConfigUrl", ctypes.c_void_p),
                    ("lpszProxy", ctypes.c_void_p),
                    ("lpszProxyBypass", ctypes.c_void_p)]

    _winhttp = ctypes.WinDLL("winhttp", use_last_error=True)
    _winhttp.WinHttpOpen.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPCWSTR,
                                     wintypes.LPCWSTR, wintypes.DWORD]
    _winhttp.WinHttpOpen.restype = ctypes.c_void_p  # HINTERNET
    _winhttp.WinHttpCloseHandle.argtypes = [ctypes.c_void_p]
    _winhttp.WinHttpCloseHandle.restype = wintypes.BOOL
    _winhttp.WinHttpGetProxyForUrl.argtypes = [
        ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(_AutoProxyOptions),
        ctypes.POINTER(_ProxyInfo)]
    _winhttp.WinHttpGetProxyForUrl.restype = wintypes.BOOL
    _winhttp.WinHttpGetIEProxyConfigForCurrentUser.argtypes = [
        ctypes.POINTER(_IEProxyConfig)]
    _winhttp.WinHttpGetIEProxyConfigForCurrentUser.restype = wintypes.BOOL
    _kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
    _kernel32.GlobalFree.restype = ctypes.c_void_p

    def _take_string(ptr):
        if not ptr:
            return None
        try:
            return ctypes.wstring_at(ptr)
        finally:
            _kernel32.GlobalFree(ptr)

    class WinHttpResult(namedtuple("WinHttpResult", "ok error access_type proxy bypass")):
        """One WinHttpGetProxyForUrl answer; error is its GetLastError()."""
        __slots__ = ()

        @property
        def direct(self):
            return self.ok and (self.access_type == WINHTTP_ACCESS_TYPE_NO_PROXY
                                or not self.proxy)

        def names_proxy(self, addr):
            return (self.ok and self.access_type == WINHTTP_ACCESS_TYPE_NAMED_PROXY
                    and addr in (self.proxy or ""))

    def winhttp_proxy_for_url(url, pac_url, in_process=False):
        """Ask WinHTTP's PAC engine which proxy url should use under the
        script at pac_url. Out of process (WinHTTP's autoproxy service, as
        most apps run it) unless in_process."""
        session = _winhttp.WinHttpOpen("SNIper-pytest", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                       None, None, 0)
        if not session:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            options = _AutoProxyOptions()
            options.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL
            if in_process:
                options.dwFlags |= WINHTTP_AUTOPROXY_RUN_INPROCESS
            options.lpszAutoConfigUrl = pac_url
            options.fAutoLogonIfChallenged = False
            info = _ProxyInfo()
            if not _winhttp.WinHttpGetProxyForUrl(session, url, ctypes.byref(options),
                                                  ctypes.byref(info)):
                return WinHttpResult(False, ctypes.get_last_error(), None, None, None)
            return WinHttpResult(True, 0, info.dwAccessType,
                                 _take_string(info.lpszProxy),
                                 _take_string(info.lpszProxyBypass))
        finally:
            _winhttp.WinHttpCloseHandle(session)

    def winhttp_ie_config():
        """What WinHTTP reports as the current user's proxy configuration:
        {auto_detect, auto_config_url, proxy, proxy_bypass}. Read-only."""
        config = _IEProxyConfig()
        if not _winhttp.WinHttpGetIEProxyConfigForCurrentUser(ctypes.byref(config)):
            raise ctypes.WinError(ctypes.get_last_error())
        return {"auto_detect": bool(config.fAutoDetect),
                "auto_config_url": _take_string(config.lpszAutoConfigUrl),
                "proxy": _take_string(config.lpszProxy),
                "proxy_bypass": _take_string(config.lpszProxyBypass)}
