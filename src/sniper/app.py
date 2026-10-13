"""Top-level bootstrap: the session-local single-instance guard, the shutdown
priority, and main(). The window (sniper.ui, and with it tkinter) is imported
only inside main(), so this module imports on a host without tkinter.
"""
from __future__ import annotations

import ctypes

from sniper.compat import IS_WINDOWS

# user32 for the "already running" message box, kernel32 for the shutdown
# priority below.
if IS_WINDOWS:
    from ctypes import wintypes

    _user32 = ctypes.windll.user32
    _kernel32 = ctypes.windll.kernel32
    _kernel32.SetProcessShutdownParameters.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.SetProcessShutdownParameters.restype  = wintypes.BOOL

# Highest level an application may use (0x300-0x3FF is the "first to shut
# down" application range; 0x400+ is reserved for the system).
_SHUTDOWN_LEVEL = 0x3FF


# ── Single-instance guard ─────────────────────────────────────────────────────
_singleton_mutex = None  # kept for the process lifetime so the mutex stays held


def _acquire_single_instance():
    """Return False if another SNIper instance is already running this session.

    Two instances would both manage the per-user proxy registry keys and
    fight over saving and restoring them, so a double launch is blocked. The
    named mutex is session-local (no 'Global\\' prefix), so separate Windows
    logon sessions (RDP, Fast User Switching) each run their own instance.
    The handle is never closed — Windows releases it when the process exits.
    """
    global _singleton_mutex
    if not IS_WINDOWS:
        return True
    try:
        k = ctypes.windll.kernel32
        k.CreateMutexW.restype  = ctypes.c_void_p
        k.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        handle = k.CreateMutexW(None, False, "SNIper_singleton")
        already_running = k.GetLastError() == 183  # ERROR_ALREADY_EXISTS
    except (OSError, AttributeError):
        return True  # never block startup if the guard itself fails
    if not handle:
        return True
    if already_running:
        return False
    _singleton_mutex = handle
    return True


def _raise_shutdown_priority():
    """Ask Windows to send SNIper its session-end messages early.

    Windows notifies processes from the highest shutdown level down. Going
    early means the system proxy is restored before some other, hung app can
    make the user pick "Shut down anyway", after which nobody is asked any
    more. Best effort: a failure changes nothing else.
    """
    if not IS_WINDOWS:
        return
    try:
        _kernel32.SetProcessShutdownParameters(_SHUTDOWN_LEVEL, 0)
    except Exception:
        pass


def main():
    if not _acquire_single_instance():
        if IS_WINDOWS:
            _user32.MessageBoxW(
                0,
                "SNIper is already running.\n\n"
                "Look for its window, or its icon in the system tray.",
                "SNIper",
                0x40,  # MB_OK | MB_ICONINFORMATION
            )
        raise SystemExit(0)
    _raise_shutdown_priority()
    from sniper.ui import App
    app = App()
    app.mainloop()
