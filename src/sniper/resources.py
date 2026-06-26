"""Locate the bundled SNIper.ico, shared by the window and the tray icon."""
from __future__ import annotations

import os


def _icon_path():
    """Absolute path to SNIper.ico, or None if it cannot be located.

    Packager-independent: this never consults ``sys.frozen`` / ``sys._MEIPASS``
    (those are PyInstaller-only and absent under Nuitka). Both supported run
    modes place the icon at a path relative to *this* module's ``__file__``,
    so the first candidate that exists wins:

    * Compiled build (Nuitka onefile / standalone): the build embeds SNIper.ico
      beside this package, so it travels inside the single EXE no matter where
      the EXE is moved. At runtime the compiled module's ``__file__`` points
      into the unpacked program directory and the icon sits next to this file.
      The build wires this up with ``--include-data-files=...=sniper/SNIper.ico``;
      that target and the first candidate below must stay in sync.
    * Plain script run from the source tree: the icon lives in the repo's
      packaging/ folder, two levels up from src/sniper/.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = (
        os.path.join(here, "SNIper.ico"),                            # compiled build
        os.path.join(here, "..", "..", "packaging", "SNIper.ico"),   # source tree
    )
    for candidate in candidates:
        candidate = os.path.normpath(candidate)
        if os.path.isfile(candidate):
            return candidate
    return None


ICON_PATH = _icon_path()  # resolved once at import; None if the .ico is absent
