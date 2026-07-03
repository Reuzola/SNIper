"""Locate the bundled SNIper.ico, shared by the window and the tray icon."""
from __future__ import annotations

import os
import sys


def _icon_path():
    """Absolute path to SNIper.ico, or None if it cannot be located.

    Frozen (PyInstaller onefile): the icon is bundled with the program and
    extracted next to it (sys._MEIPASS), so it travels inside the single EXE
    no matter where the EXE is moved. Run as a plain script: it lives in the
    repo's packaging/ folder, two levels up from src/sniper/.
    """
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        candidate = os.path.join(base, "SNIper.ico")
    else:
        candidate = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "..", "..", "packaging", "SNIper.ico")
    candidate = os.path.normpath(candidate)
    return candidate if os.path.isfile(candidate) else None


ICON_PATH = _icon_path()  # resolved once at import; None if the .ico is absent
