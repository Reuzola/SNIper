"""System tray icon (Win32 Shell_NotifyIcon - pure ctypes).

All Win32 structs and bound argtypes live inside an ``if IS_WINDOWS:`` block,
so the module imports cleanly on any OS; ``TrayIcon`` methods early-return
when the platform is unsupported. Logic unchanged from the embedded original;
the platform flag and icon path now come from sniper.compat / sniper.resources.
"""
from __future__ import annotations

import ctypes
import threading

from sniper.compat import IS_WINDOWS
from sniper.resources import ICON_PATH


if IS_WINDOWS:
    from ctypes import wintypes

    _user32   = ctypes.windll.user32
    _shell32  = ctypes.windll.shell32
    _kernel32 = ctypes.windll.kernel32

    _WM_DESTROY      = 0x0002
    _WM_COMMAND      = 0x0111
    _WM_LBUTTONUP    = 0x0202
    _WM_LBUTTONDBLCLK= 0x0203
    _WM_RBUTTONUP    = 0x0205
    _WM_USER         = 0x0400
    _WM_TRAY_CB      = _WM_USER + 1

    _NIM_ADD    = 0x00000000
    _NIM_MODIFY = 0x00000001
    _NIM_DELETE = 0x00000002
    _NIF_MESSAGE= 0x00000001
    _NIF_ICON   = 0x00000002
    _NIF_TIP    = 0x00000004

    _IDI_APPLICATION = 32512
    _IDC_ARROW       = 32512

    # LoadImageW flags and GetSystemMetrics index for loading the app icon
    # from the bundled SNIper.ico file at runtime.
    _IMAGE_ICON      = 1
    _LR_LOADFROMFILE = 0x00000010
    _SM_CXSMICON     = 49

    # The tray helper window is a normal (never-shown) top-level window, not
    # a message-only window: message-only windows do not receive broadcast
    # messages, and the TaskbarCreated notification (section 8.1) is sent as
    # a broadcast. WS_EX_TOOLWINDOW keeps the hidden window off the taskbar
    # and out of the Alt-Tab list.
    _WS_EX_TOOLWINDOW = 0x00000080

    _TPM_RIGHTBUTTON = 0x0002
    _TPM_RETURNCMD   = 0x0100
    _TPM_NONOTIFY    = 0x0080

    _MF_STRING    = 0x00000000
    _MF_SEPARATOR = 0x00000800

    # WPARAM / LPARAM / LRESULT are pointer-sized in the real Win32 ABI.
    # Python's wintypes defines them as 32-bit, which corrupts arguments on
    # x64. Use pointer-sized types instead.
    _WPARAM  = ctypes.c_size_t
    _LPARAM  = ctypes.c_ssize_t
    _LRESULT = ctypes.c_ssize_t
    _UINT_PTR= ctypes.c_size_t

    _WNDPROC = ctypes.WINFUNCTYPE(
        _LRESULT,
        wintypes.HWND, wintypes.UINT, _WPARAM, _LPARAM,
    )

    class _WNDCLASSW(ctypes.Structure):
        _fields_ = [
            ("style",         wintypes.UINT),
            ("lpfnWndProc",   _WNDPROC),
            ("cbClsExtra",    ctypes.c_int),
            ("cbWndExtra",    ctypes.c_int),
            ("hInstance",     wintypes.HINSTANCE),
            ("hIcon",         wintypes.HICON),
            ("hCursor",       wintypes.HANDLE),
            ("hbrBackground", wintypes.HBRUSH),
            ("lpszMenuName",  wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
        ]

    class _POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

    class _MSG(ctypes.Structure):
        _fields_ = [
            ("hwnd",    wintypes.HWND),
            ("message", wintypes.UINT),
            ("wParam",  _WPARAM),
            ("lParam",  _LPARAM),
            ("time",    wintypes.DWORD),
            ("pt",      _POINT),
        ]

    class _NOTIFYICONDATAW(ctypes.Structure):
        _fields_ = [
            ("cbSize",          wintypes.DWORD),
            ("hWnd",            wintypes.HWND),
            ("uID",             wintypes.UINT),
            ("uFlags",          wintypes.UINT),
            ("uCallbackMessage",wintypes.UINT),
            ("hIcon",           wintypes.HICON),
            ("szTip",           wintypes.WCHAR * 128),
            ("dwState",         wintypes.DWORD),
            ("dwStateMask",     wintypes.DWORD),
            ("szInfo",          wintypes.WCHAR * 256),
            ("uVersion",        wintypes.DWORD),
            ("szInfoTitle",     wintypes.WCHAR * 64),
            ("dwInfoFlags",     wintypes.DWORD),
            ("guidItem",        ctypes.c_byte * 16),
            ("hBalloonIcon",    wintypes.HICON),
        ]

    # Bind argtypes/restype for everything we call. Without this, ctypes
    # passes ints as 32-bit c_int, which truncates pointers / handles on x64.
    _user32.DefWindowProcW.argtypes = [
        wintypes.HWND, wintypes.UINT, _WPARAM, _LPARAM,
    ]
    _user32.DefWindowProcW.restype  = _LRESULT

    _user32.GetMessageW.argtypes = [
        ctypes.POINTER(_MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT,
    ]
    _user32.GetMessageW.restype  = ctypes.c_int

    _user32.TranslateMessage.argtypes  = [ctypes.POINTER(_MSG)]
    _user32.TranslateMessage.restype   = wintypes.BOOL
    _user32.DispatchMessageW.argtypes  = [ctypes.POINTER(_MSG)]
    _user32.DispatchMessageW.restype   = _LRESULT

    _user32.PostMessageW.argtypes = [
        wintypes.HWND, wintypes.UINT, _WPARAM, _LPARAM,
    ]
    _user32.PostMessageW.restype  = wintypes.BOOL

    _user32.PostQuitMessage.argtypes = [ctypes.c_int]
    _user32.PostQuitMessage.restype  = None

    _user32.LoadIconW.argtypes   = [wintypes.HINSTANCE, wintypes.LPCWSTR]
    _user32.LoadIconW.restype    = wintypes.HICON
    _user32.LoadCursorW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
    _user32.LoadCursorW.restype  = wintypes.HANDLE

    _user32.LoadImageW.argtypes  = [
        wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT,
        ctypes.c_int, ctypes.c_int, wintypes.UINT,
    ]
    _user32.LoadImageW.restype   = wintypes.HANDLE
    _user32.GetSystemMetrics.argtypes = [ctypes.c_int]
    _user32.GetSystemMetrics.restype  = ctypes.c_int

    _user32.RegisterClassW.argtypes = [ctypes.POINTER(_WNDCLASSW)]
    _user32.RegisterClassW.restype  = wintypes.ATOM

    _user32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
    _user32.RegisterWindowMessageW.restype  = wintypes.UINT

    # Explorer broadcasts "TaskbarCreated" to every top-level window when the
    # taskbar is (re)built — e.g. after an Explorer crash and restart. The
    # registered id is the same for every process that asks for it.
    _TASKBAR_CREATED = _user32.RegisterWindowMessageW("TaskbarCreated")

    _user32.CreateWindowExW.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
    ]
    _user32.CreateWindowExW.restype = wintypes.HWND

    _user32.CreatePopupMenu.argtypes = []
    _user32.CreatePopupMenu.restype  = wintypes.HMENU
    _user32.AppendMenuW.argtypes = [
        wintypes.HMENU, wintypes.UINT, _UINT_PTR, wintypes.LPCWSTR,
    ]
    _user32.AppendMenuW.restype  = wintypes.BOOL
    _user32.TrackPopupMenu.argtypes = [
        wintypes.HMENU, wintypes.UINT,
        ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, ctypes.c_void_p,
    ]
    _user32.TrackPopupMenu.restype  = wintypes.BOOL
    _user32.DestroyMenu.argtypes = [wintypes.HMENU]
    _user32.DestroyMenu.restype  = wintypes.BOOL
    _user32.GetCursorPos.argtypes = [ctypes.POINTER(_POINT)]
    _user32.GetCursorPos.restype  = wintypes.BOOL
    _user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    _user32.SetForegroundWindow.restype  = wintypes.BOOL

    _shell32.Shell_NotifyIconW.argtypes = [
        wintypes.DWORD, ctypes.POINTER(_NOTIFYICONDATAW),
    ]
    _shell32.Shell_NotifyIconW.restype  = wintypes.BOOL

    _shell32.SetCurrentProcessExplicitAppUserModelID.argtypes = [wintypes.LPCWSTR]
    _shell32.SetCurrentProcessExplicitAppUserModelID.restype  = ctypes.c_long

    _kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    _kernel32.GetModuleHandleW.restype  = wintypes.HMODULE

    def _MAKEINTRESOURCE(i):
        # Win32 stock IDs are passed as LPCWSTR with the pointer value being
        # the small integer. ctypes won't auto-convert int→LPCWSTR; cast it.
        return ctypes.cast(ctypes.c_void_p(i), wintypes.LPCWSTR)

    _tray_hicon_cache = None

    def _tray_hicon():
        """HICON for the tray, loaded once from SNIper.ico at small-icon size.

        Falls back to the generic Windows application icon if the bundled
        .ico is missing, so the tray entry is never blank. The handle lives
        for the whole process; Windows reclaims it when the process exits.
        """
        global _tray_hicon_cache
        if _tray_hicon_cache is None and ICON_PATH:
            size = _user32.GetSystemMetrics(_SM_CXSMICON)
            _tray_hicon_cache = _user32.LoadImageW(
                None, ICON_PATH, _IMAGE_ICON, size, size, _LR_LOADFROMFILE)
        if not _tray_hicon_cache:
            _tray_hicon_cache = _user32.LoadIconW(
                None, _MAKEINTRESOURCE(_IDI_APPLICATION))
        return _tray_hicon_cache


class TrayIcon:
    """
    Minimal Windows system-tray icon driven by Shell_NotifyIcon.

    A dedicated thread owns a hidden message-only window and pumps messages.
    Tray events are forwarded to the supplied callbacks via tk_after, which
    must marshal the call back onto the Tk main thread (use root.after(0, ...)).
    """

    _MENU_SHOW   = 1001
    _MENU_TOGGLE = 1002
    _MENU_EXIT   = 1003

    def __init__(self, on_show, on_toggle, on_exit, is_running, tk_after,
                 tooltip="SNIper"):
        self.on_show    = on_show
        self.on_toggle  = on_toggle
        self.on_exit    = on_exit
        self.is_running = is_running   # callable -> bool, queried at menu open
        self.tk_after   = tk_after
        self.tooltip    = tooltip

        self._hwnd        = None
        self._wndproc_ref = None  # keep WNDPROC alive
        self._cls_name    = f"SNIperTray_{id(self)}"
        self._thread      = None
        self._added       = False
        self._ready       = threading.Event()
        self._supported   = IS_WINDOWS

    def start(self):
        if not self._supported:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=2.0)

    def stop(self):
        if not self._supported or self._hwnd is None:
            return
        try:
            _user32.PostMessageW(self._hwnd, _WM_DESTROY, 0, 0)
        except Exception:
            pass

    # ── internals ────────────────────────────────────────────────────────────
    def _run(self):
        hinst = _kernel32.GetModuleHandleW(None)

        def _wndproc(hwnd, msg, wparam, lparam):
            if msg == _WM_TRAY_CB:
                evt = lparam & 0xFFFF
                if evt == _WM_LBUTTONUP or evt == _WM_LBUTTONDBLCLK:
                    self.tk_after(0, self.on_show)
                elif evt == _WM_RBUTTONUP:
                    self._show_menu(hwnd)
                return 0
            if msg == _WM_COMMAND:
                cmd = wparam & 0xFFFF
                if cmd == self._MENU_SHOW:
                    self.tk_after(0, self.on_show)
                elif cmd == self._MENU_TOGGLE:
                    self.tk_after(0, self.on_toggle)
                elif cmd == self._MENU_EXIT:
                    self.tk_after(0, self.on_exit)
                return 0
            if msg == _WM_DESTROY:
                self._remove_icon()
                _user32.PostQuitMessage(0)
                return 0
            if _TASKBAR_CREATED and msg == _TASKBAR_CREATED:
                # Explorer restarted — the rebuilt taskbar dropped our icon.
                # Re-register it so it reappears instead of staying gone.
                self._added = False
                self._add_icon()
                return 0
            return _user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        self._wndproc_ref = _WNDPROC(_wndproc)

        wc = _WNDCLASSW()
        wc.style         = 0
        wc.lpfnWndProc   = self._wndproc_ref
        wc.cbClsExtra    = 0
        wc.cbWndExtra    = 0
        wc.hInstance     = hinst
        wc.hIcon         = 0
        wc.hCursor       = _user32.LoadCursorW(None, _MAKEINTRESOURCE(_IDC_ARROW))
        wc.hbrBackground = 0
        wc.lpszMenuName  = None
        wc.lpszClassName = self._cls_name

        atom = _user32.RegisterClassW(ctypes.byref(wc))
        if not atom:
            self._ready.set()
            return

        # Normal top-level window with a NULL parent (not HWND_MESSAGE): a
        # message-only window would never receive the TaskbarCreated
        # broadcast. It is never shown, and WS_EX_TOOLWINDOW keeps it off the
        # taskbar and out of Alt-Tab.
        hwnd = _user32.CreateWindowExW(
            _WS_EX_TOOLWINDOW, self._cls_name, "SNIperTray",
            0, 0, 0, 0, 0,
            0, 0, hinst, None,
        )
        if not hwnd:
            self._ready.set()
            return

        self._hwnd = hwnd
        self._add_icon()
        self._ready.set()

        msg = _MSG()
        while _user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) > 0:
            _user32.TranslateMessage(ctypes.byref(msg))
            _user32.DispatchMessageW(ctypes.byref(msg))

    def _add_icon(self):
        nid = _NOTIFYICONDATAW()
        nid.cbSize           = ctypes.sizeof(_NOTIFYICONDATAW)
        nid.hWnd             = self._hwnd
        nid.uID              = 1
        nid.uFlags           = _NIF_MESSAGE | _NIF_ICON | _NIF_TIP
        nid.uCallbackMessage = _WM_TRAY_CB
        nid.hIcon            = _tray_hicon()
        nid.szTip            = self.tooltip[:127]
        if _shell32.Shell_NotifyIconW(_NIM_ADD, ctypes.byref(nid)):
            self._added = True

    def _remove_icon(self):
        if not self._added:
            return
        nid = _NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
        nid.hWnd   = self._hwnd
        nid.uID    = 1
        _shell32.Shell_NotifyIconW(_NIM_DELETE, ctypes.byref(nid))
        self._added = False

    def _show_menu(self, hwnd):
        # Query the proxy state at menu-open time so the toggle item reflects
        # the current state instead of being a static "Stop proxy".
        try:
            running = bool(self.is_running())
        except Exception:
            running = False
        toggle_label = "Stop proxy" if running else "Start proxy"

        h_menu = _user32.CreatePopupMenu()
        _user32.AppendMenuW(h_menu, _MF_STRING, self._MENU_SHOW, "Open window")
        _user32.AppendMenuW(h_menu, _MF_STRING, self._MENU_TOGGLE, toggle_label)
        _user32.AppendMenuW(h_menu, _MF_SEPARATOR, 0, None)
        _user32.AppendMenuW(h_menu, _MF_STRING, self._MENU_EXIT, "Quit")

        pt = _POINT()
        _user32.GetCursorPos(ctypes.byref(pt))
        # Required so the menu vanishes when the user clicks elsewhere.
        _user32.SetForegroundWindow(hwnd)
        _user32.TrackPopupMenu(
            h_menu, _TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, None
        )
        _user32.PostMessageW(hwnd, 0x0000, 0, 0)  # WM_NULL — flushes
        _user32.DestroyMenu(h_menu)
