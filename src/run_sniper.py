#!/usr/bin/env python3
"""PyInstaller entry point. Keeps the package importable as ``sniper.*``
because this launcher lives in ``src/`` alongside the package directory."""
from __future__ import annotations

from sniper.app import main

if __name__ == "__main__":
    main()
