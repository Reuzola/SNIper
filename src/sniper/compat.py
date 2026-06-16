"""Platform compatibility shim.

Single source of the ``IS_WINDOWS`` flag and the guarded ``winreg`` import.
On a non-Windows / headless machine ``winreg`` is ``None`` and ``IS_WINDOWS``
is ``False``, so the rest of the package imports cleanly anywhere (every
Win32 call elsewhere is guarded behind ``IS_WINDOWS``).
"""
from __future__ import annotations

try:
    import winreg
    IS_WINDOWS = True
except ImportError:
    winreg = None
    IS_WINDOWS = False
