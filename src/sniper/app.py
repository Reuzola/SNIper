"""Top-level bootstrap: the session-local single-instance guard and main().
Logic unchanged from the embedded original; the platform flag comes from
sniper.compat and the window from sniper.ui.
"""
from __future__ import annotations

import ctypes

from sniper.compat import IS_WINDOWS
from sniper.ui import App

# user32 handle for the "already running" message box below.
if IS_WINDOWS:
    _user32 = ctypes.windll.user32


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
    app = App()
    app.mainloop()
