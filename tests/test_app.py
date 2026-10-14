"""Tests for sniper.app: the shutdown priority, the order main() does things
in, and that the bootstrap (and every non-UI module) imports without tkinter.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import types

import pytest

import sniper.app as app
from sniper.compat import IS_WINDOWS

_SRC = os.path.dirname(os.path.dirname(os.path.abspath(app.__file__)))


# ── Shutdown priority ────────────────────────────────────────────────────────
@pytest.mark.skipif(not IS_WINDOWS, reason="SetProcessShutdownParameters is Win32")
@pytest.mark.windows_integration
def test_raise_shutdown_priority_sets_level_0x3ff():
    from helpers import get_shutdown_parameters, set_shutdown_parameters
    before = get_shutdown_parameters()
    try:
        app._raise_shutdown_priority()
        level, flags = get_shutdown_parameters()
        assert level == 0x3FF
        assert flags == 0
    finally:
        set_shutdown_parameters(*before)  # this process is pytest's own


def test_raise_shutdown_priority_is_a_no_op_off_windows(monkeypatch):
    calls = []
    monkeypatch.setattr(app, "IS_WINDOWS", False)
    monkeypatch.setattr(app, "_kernel32", types.SimpleNamespace(
        SetProcessShutdownParameters=lambda *a: calls.append(a)), raising=False)
    app._raise_shutdown_priority()
    assert calls == []


def test_raise_shutdown_priority_ignores_failures(monkeypatch):
    def boom(*args):
        raise OSError("denied")
    monkeypatch.setattr(app, "IS_WINDOWS", True)
    monkeypatch.setattr(app, "_kernel32", types.SimpleNamespace(
        SetProcessShutdownParameters=boom), raising=False)
    app._raise_shutdown_priority()


# ── main() ───────────────────────────────────────────────────────────────────
def test_main_raises_priority_after_the_instance_check_then_opens_the_ui(monkeypatch):
    pytest.importorskip("tkinter")
    import sniper.ui as ui
    order = []

    class FakeApp:
        def __init__(self):
            order.append("App")

        def mainloop(self):
            order.append("mainloop")

    monkeypatch.setattr(app, "_acquire_single_instance",
                        lambda: order.append("single-instance") or True)
    monkeypatch.setattr(app, "_raise_shutdown_priority",
                        lambda: order.append("priority"))
    monkeypatch.setattr(ui, "App", FakeApp)
    app.main()
    assert order == ["single-instance", "priority", "App", "mainloop"]


def test_main_second_instance_exits_without_touching_anything(monkeypatch):
    order = []
    monkeypatch.setattr(app, "_acquire_single_instance", lambda: False)
    monkeypatch.setattr(app, "_raise_shutdown_priority",
                        lambda: order.append("priority"))
    monkeypatch.setattr(app, "_user32", types.SimpleNamespace(
        MessageBoxW=lambda *a: order.append("message")), raising=False)
    with pytest.raises(SystemExit) as exc:
        app.main()
    assert exc.value.code == 0
    assert "priority" not in order


# ── Imports without tkinter / winreg ─────────────────────────────────────────
def _run(code):
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code), _SRC],
                          capture_output=True, text=True, timeout=60)


def test_app_imports_without_tkinter():
    proc = _run("""
        import sys
        sys.modules["tkinter"] = None
        sys.path.insert(0, sys.argv[1])
        import sniper.app
        assert "sniper.ui" not in sys.modules
        assert callable(sniper.app.main)
    """)
    assert proc.returncode == 0, proc.stderr


def test_non_ui_modules_import_on_a_headless_host():
    # As on a non-Windows host without Tk: neither module can be imported.
    proc = _run("""
        import sys
        sys.modules["tkinter"] = None
        sys.modules["winreg"] = None
        sys.path.insert(0, sys.argv[1])
        import sniper.compat
        assert not sniper.compat.IS_WINDOWS
        for name in ("app", "server", "sessionwatch", "winproxy", "settings",
                     "tray", "proxy", "pac", "dns", "logformat", "config",
                     "resources", "guardian", "procutil"):
            __import__("sniper." + name)
        from sniper.sessionwatch import SessionEndWatcher
        w = SessionEndWatcher(None, None)
        w.start(); w.stop()
        assert not w.ok
        # Without Windows there is nothing to guard or lock.
        import sniper.guardian, sniper.procutil, sniper.winproxy
        assert sniper.guardian.spawn_guardian("0123456789abcdef") is False
        assert sniper.guardian.notify_restored() is False
        assert sniper.procutil.open_for_wait(1, 1) is None
        with sniper.winproxy._state_lock() as acquired:
            assert acquired is False
        assert sniper.winproxy.current_session_id() is None
    """)
    assert proc.returncode == 0, proc.stderr
