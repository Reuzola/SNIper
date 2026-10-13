#!/usr/bin/env python3
"""Manual-test helper: a visible window that blocks Windows sign-out.

It lets a human test both of SNIper's session-end paths. While this window
is open, signing out (or restarting) stops at Windows' "apps are preventing
sign-out" screen, which lists this window with the reason below:

- press Cancel: Windows tells every app the sign-out was cancelled, and
  SNIper logs "Sign-out was cancelled — system proxy re-applied.";
- press "Sign out anyway": the session ends; SNIper had already restored the
  proxy when the sign-out began.

Close the window to stop blocking. Standard library only and independent of
SNIper. Not collected by pytest (no test_ prefix) and not part of the EXE.

Usage:  python tests\\manual\\block_shutdown.py
"""
from __future__ import annotations

import ctypes
import sys

TITLE = "SNIper test — blocking sign-out"
REASON = "Testing SNIper's cancelled sign-out path"

WM_DESTROY         = 0x0002
WM_CLOSE           = 0x0010
WM_QUERYENDSESSION = 0x0011
WM_ENDSESSION      = 0x0016
WS_OVERLAPPEDWINDOW = 0x00CF0000
WS_VISIBLE         = 0x10000000
WS_CHILD           = 0x40000000
CW_USEDEFAULT      = -0x80000000
COLOR_WINDOW       = 5
SW_SHOW            = 5
IDC_ARROW          = 32512


def main():
    if sys.platform != "win32":
        print("Windows only")
        return 0
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # WPARAM / LPARAM / LRESULT are pointer-sized.
    WPARAM, LPARAM, LRESULT = ctypes.c_size_t, ctypes.c_ssize_t, ctypes.c_ssize_t
    WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, WPARAM, LPARAM)

    class WNDCLASSW(ctypes.Structure):
        _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", WNDPROC),
                    ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                    ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON),
                    ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
                    ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR)]

    class MSG(ctypes.Structure):
        _fields_ = [("hwnd", wintypes.HWND), ("message", wintypes.UINT),
                    ("wParam", WPARAM), ("lParam", LPARAM), ("time", wintypes.DWORD),
                    ("pt", wintypes.POINT)]

    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM, LPARAM]
    user32.DefWindowProcW.restype = LRESULT
    user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
    user32.RegisterClassW.restype = wintypes.ATOM
    user32.CreateWindowExW.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.ShowWindow.restype = wintypes.BOOL
    user32.LoadCursorW.argtypes = [wintypes.HINSTANCE, wintypes.LPVOID]
    user32.LoadCursorW.restype = wintypes.HANDLE
    user32.GetMessageW.argtypes = [ctypes.POINTER(MSG), wintypes.HWND,
                                   wintypes.UINT, wintypes.UINT]
    user32.GetMessageW.restype = wintypes.BOOL
    user32.TranslateMessage.argtypes = [ctypes.POINTER(MSG)]
    user32.TranslateMessage.restype = wintypes.BOOL
    user32.DispatchMessageW.argtypes = [ctypes.POINTER(MSG)]
    user32.DispatchMessageW.restype = LRESULT
    user32.PostQuitMessage.argtypes = [ctypes.c_int]
    user32.PostQuitMessage.restype = None
    user32.ShutdownBlockReasonCreate.argtypes = [wintypes.HWND, wintypes.LPCWSTR]
    user32.ShutdownBlockReasonCreate.restype = wintypes.BOOL
    user32.ShutdownBlockReasonDestroy.argtypes = [wintypes.HWND]
    user32.ShutdownBlockReasonDestroy.restype = wintypes.BOOL

    def wndproc(hwnd, msg, wparam, lparam):
        try:
            if msg == WM_QUERYENDSESSION:
                # The reason is what Windows shows next to this window on the
                # "apps are preventing sign-out" screen.
                user32.ShutdownBlockReasonCreate(hwnd, REASON)
                print("WM_QUERYENDSESSION: refused (blocking).", flush=True)
                return 0
            if msg == WM_ENDSESSION:
                if wparam:
                    print("WM_ENDSESSION(TRUE): the session is ending anyway.", flush=True)
                else:
                    print("WM_ENDSESSION(FALSE): sign-out cancelled. Check SNIper's log.",
                          flush=True)
                return 0
            if msg == WM_DESTROY:
                user32.ShutdownBlockReasonDestroy(hwnd)
                user32.PostQuitMessage(0)
                return 0
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)
        except Exception as e:  # never let an exception escape a window procedure
            print("window procedure error: %r" % (e,), flush=True)
            return 0

    proc = WNDPROC(wndproc)
    hinst = kernel32.GetModuleHandleW(None)
    wc = WNDCLASSW()
    wc.lpfnWndProc = proc
    wc.hInstance = hinst
    wc.hCursor = user32.LoadCursorW(None, ctypes.c_void_p(IDC_ARROW))
    wc.hbrBackground = wintypes.HBRUSH(COLOR_WINDOW + 1)
    wc.lpszClassName = "SNIperTestBlockShutdown"
    if not user32.RegisterClassW(ctypes.byref(wc)):
        raise ctypes.WinError(ctypes.get_last_error())

    hwnd = user32.CreateWindowExW(0, wc.lpszClassName, TITLE,
                                  WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                  CW_USEDEFAULT, CW_USEDEFAULT, 560, 150,
                                  None, None, hinst, None)
    if not hwnd:
        raise ctypes.WinError(ctypes.get_last_error())
    user32.CreateWindowExW(
        0, "STATIC",
        "This window blocks sign-out and restart so SNIper's cancel path can be "
        "tested.\nSign out, then press Cancel or \"Sign out anyway\". "
        "Close this window to stop blocking.",
        WS_CHILD | WS_VISIBLE, 12, 12, 520, 80, hwnd, None, hinst, None)
    user32.ShowWindow(hwnd, SW_SHOW)
    print("Blocking sign-out. Close the window to stop.", flush=True)

    msg = MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
