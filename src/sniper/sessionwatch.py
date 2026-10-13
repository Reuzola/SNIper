"""Turn Windows sign-out / restart / shutdown into synchronous callbacks.

A console control handler can't do this job: Windows never sends
CTRL_LOGOFF_EVENT / CTRL_SHUTDOWN_EVENT to a process that has loaded user32
(every Tk app), and the EXE has no console anyway. What Microsoft recommends
instead is a hidden top-level window that handles WM_QUERYENDSESSION and
WM_ENDSESSION. It has to be a real top-level window: a message-only
(HWND_MESSAGE) window never receives these messages.

The window lives on its own thread with its own message loop, so it answers
even while the Tk main thread is busy, and the callbacks run right there,
inside the window procedure. They must not be handed to Tk with after():
once WM_ENDSESSION returns, the session can end at any moment, so work that
was merely scheduled may never run.

handle_session_message() holds the message logic and is plain Python, so it
is tested on any OS; the window itself exists on Windows only. Win32 bindings
are reused from sniper.tray, and everything new is bound with full
argtypes/restype.
"""
from __future__ import annotations

import ctypes
import threading

from sniper.compat import IS_WINDOWS

WM_DESTROY         = 0x0002
WM_CLOSE           = 0x0010
WM_QUERYENDSESSION = 0x0011
WM_ENDSESSION      = 0x0016


def _call_quietly(callback):
    try:
        callback()
    except Exception:
        pass


def handle_session_message(msg, wparam, on_ending, on_cancelled):
    """Return the LRESULT for WM_QUERYENDSESSION / WM_ENDSESSION, or None for
    any other message. Callbacks run synchronously; their exceptions are
    swallowed.

    on_ending runs for WM_QUERYENDSESSION and again for WM_ENDSESSION(TRUE):
    it is idempotent, and a forced shutdown may skip the query and send only
    the end. on_cancelled runs for WM_ENDSESSION(FALSE), when the sign-out or
    shutdown was cancelled after all. SNIper never vetoes a session end.
    """
    if msg == WM_QUERYENDSESSION:
        _call_quietly(on_ending)
        return 1
    if msg == WM_ENDSESSION:
        _call_quietly(on_ending if wparam else on_cancelled)
        return 0
    return None


if IS_WINDOWS:
    from ctypes import wintypes

    from sniper.tray import (
        _MSG, _WNDCLASSW, _WNDPROC, _WS_EX_TOOLWINDOW, _kernel32, _user32,
    )

    _user32.DestroyWindow.argtypes = [wintypes.HWND]
    _user32.DestroyWindow.restype  = wintypes.BOOL
    _user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
    _user32.UnregisterClassW.restype  = wintypes.BOOL


class SessionEndWatcher:
    """Hidden window on a daemon thread that calls on_ending() when Windows
    is about to end the session and on_cancelled() if that is called off.

    start() returns once the window exists (or after 2 s at most); ok tells
    whether it does. stop() asks the window to close and returns at once. On
    other platforms both are no-ops and ok is False.
    """

    def __init__(self, on_ending, on_cancelled):
        self._on_ending    = on_ending
        self._on_cancelled = on_cancelled
        self._hwnd         = None
        self._wndproc_ref  = None  # keep the WNDPROC alive
        # Unique per instance, so watchers can come and go in one process.
        self._cls_name     = f"SNIperSessionWatch_{id(self)}"
        self._thread       = None
        self._ready        = threading.Event()
        self._destroyed    = False  # WM_DESTROY seen: the window is gone
        self._supported    = IS_WINDOWS

    @property
    def hwnd(self):
        return self._hwnd

    @property
    def thread(self):
        return self._thread

    @property
    def ok(self):
        return bool(self._hwnd) and self._thread is not None and self._thread.is_alive()

    def start(self):
        if not self._supported or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="SNIperSessionWatch",
                                        daemon=True)
        self._thread.start()
        self._ready.wait(timeout=2.0)

    def stop(self):
        hwnd = self._hwnd
        if not self._supported or not hwnd:
            return
        try:
            # WM_CLOSE -> DestroyWindow -> WM_DESTROY -> PostQuitMessage.
            _user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
        except Exception:
            pass

    # ── internals ────────────────────────────────────────────────────────────
    def _run(self):
        try:
            self._pump()
        except Exception:
            pass
        finally:
            self._hwnd = None
            self._ready.set()

    def _wndproc(self, hwnd, msg, wparam, lparam):
        try:
            result = handle_session_message(msg, wparam, self._on_ending,
                                            self._on_cancelled)
            if result is not None:
                return result
            if msg == WM_DESTROY:
                self._destroyed = True
                _user32.PostQuitMessage(0)
                return 0
            return _user32.DefWindowProcW(hwnd, msg, wparam, lparam)
        except Exception:
            # An exception escaping a ctypes callback makes it return 0,
            # which for WM_QUERYENDSESSION would veto the sign-out.
            return 1 if msg == WM_QUERYENDSESSION else 0

    def _pump(self):
        hinst = _kernel32.GetModuleHandleW(None)
        self._wndproc_ref = _WNDPROC(self._wndproc)

        wc = _WNDCLASSW()
        wc.lpfnWndProc   = self._wndproc_ref
        wc.hInstance     = hinst
        wc.lpszClassName = self._cls_name
        if not _user32.RegisterClassW(ctypes.byref(wc)):
            return
        try:
            # A normal top-level window with no parent, never shown;
            # WS_EX_TOOLWINDOW keeps it off the taskbar and out of Alt-Tab.
            hwnd = _user32.CreateWindowExW(
                _WS_EX_TOOLWINDOW, self._cls_name, "SNIperSessionWatch",
                0, 0, 0, 0, 0, None, None, hinst, None)
            if not hwnd:
                return
            self._hwnd = hwnd
            self._ready.set()
            try:
                msg = _MSG()
                while _user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                    _user32.TranslateMessage(ctypes.byref(msg))
                    _user32.DispatchMessageW(ctypes.byref(msg))
            finally:
                if not self._destroyed:
                    _user32.DestroyWindow(hwnd)
        finally:
            _user32.UnregisterClassW(self._cls_name, hinst)
