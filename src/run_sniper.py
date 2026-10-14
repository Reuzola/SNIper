#!/usr/bin/env python3
"""PyInstaller entry point. Keeps the package importable as ``sniper.*``
because this launcher lives in ``src/`` alongside the package directory."""
from __future__ import annotations

import sys

# The guardian's process modes (sniper.guardian) are routed before the app is
# even imported: they never take the single-instance mutex, never open the
# window and never import tkinter. PyInstaller still finds this import.
if len(sys.argv) > 1 and sys.argv[1] in ("--guard", "--spawn-guard", "--selftest-owner"):
    from sniper.guardian import dispatch
    raise SystemExit(dispatch(sys.argv[1:]))

from sniper.app import main  # noqa: E402

if __name__ == "__main__":
    main()
