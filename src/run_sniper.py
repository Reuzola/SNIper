#!/usr/bin/env python3
"""Application / build entry point. Keeps the package importable as ``sniper.*``
because this launcher lives in ``src/`` alongside the package directory. Used
for ``python src/run_sniper.py`` and as the entry script the EXE is built from."""
from __future__ import annotations

from sniper.app import main

if __name__ == "__main__":
    main()
