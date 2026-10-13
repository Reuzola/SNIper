"""Tests for the App's close paths, unexpected-stop handling and log cap.

The real App window is built, but ProxyServer, TrayIcon, SessionEndWatcher,
the settings store and atexit.register are replaced by fakes, so nothing here
touches the registry or leaves a hook behind. No Tk event loop runs: the
methods under test are called directly on the Tk main (test) thread.
"""
from __future__ import annotations

import queue
import threading

import pytest

from sniper.compat import IS_WINDOWS

pytestmark = pytest.mark.skipif(not IS_WINDOWS, reason="the App is Windows-only")


class FakeProxy:
    def __init__(self):
        self.log_q = queue.Queue()
        self.running = False
        self.has_session = False
        self.unexpected = False
        self.recovered = 0
        self.starts = []
        self.stops = []    # thread ident of each stop() call

    def recover(self):
        self.recovered += 1

    def start(self, port, frag, use_doh):
        self.starts.append((port, frag, use_doh))
        self.running = self.has_session = True

    def stop(self):
        self.stops.append(threading.get_ident())
        self.running = self.has_session = False

    def take_unexpected_stop(self):
        was, self.unexpected = self.unexpected, False
        return was

    def session_ending(self):
        pass

    def session_end_cancelled(self):
        pass


class FakeTray:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.is_running = kwargs["is_running"]
        self.started = self.stopped = 0

    def start(self):
        self.started += 1

    def stop(self):
        self.stopped += 1


class FakeWatcher:
    def __init__(self, on_ending, on_cancelled):
        self.on_ending = on_ending
        self.on_cancelled = on_cancelled
        self.started = self.stopped = 0

    def start(self):
        self.started += 1

    def stop(self):
        self.stopped += 1


def _must_not_be_called(*args, **kwargs):
    raise AssertionError("the settings store must not be touched")


@pytest.fixture(scope="module")
def tk_usable():
    tk = pytest.importorskip("tkinter")
    try:
        probe = tk.Tk()
    except tk.TclError as e:
        pytest.skip("Tk is not usable here: %s" % e)
    probe.destroy()


@pytest.fixture
def app(tk_usable, monkeypatch):
    import atexit

    import sniper.ui as ui
    monkeypatch.setattr(ui, "ProxyServer", FakeProxy)
    monkeypatch.setattr(ui, "TrayIcon", FakeTray)
    monkeypatch.setattr(ui, "SessionEndWatcher", FakeWatcher)
    monkeypatch.setattr(ui, "load_settings", lambda: None)
    monkeypatch.setattr(ui, "save_settings", _must_not_be_called)
    monkeypatch.setattr(ui, "clear_settings", _must_not_be_called)
    registered = []
    monkeypatch.setattr(atexit, "register", registered.append)

    a = ui.App()
    a.atexit_registered = registered
    a.destroyed = 0
    real_destroy = a.destroy

    def destroy():
        a.destroyed += 1
        real_destroy()

    a.destroy = destroy
    a.withdraw()
    yield a
    if not a.destroyed:
        a.destroy()


def log_lines(a):
    text = a._log.get("1.0", "end-1c")
    return text.split("\n")[:-1] if text else []


def test_init_wires_everything(app):
    assert app.proxy.recovered == 1
    w = app._session_watch
    assert isinstance(w, FakeWatcher) and w.started == 1
    assert w.on_ending == app.proxy.session_ending
    assert w.on_cancelled == app.proxy.session_end_cancelled
    assert app.atexit_registered == [app._ensure_stop]
    assert not hasattr(app, "_install_console_handler")
    # The tray's menu label follows the session, like the Start/Stop button.
    app.proxy.has_session, app.proxy.running = True, False
    assert app._tray.is_running() is True


def test_on_close_without_session_stops_synchronously(app):
    app._on_close()
    assert app.proxy.stops == [threading.get_ident()]
    assert app._tray.stopped >= 1
    assert app._session_watch.stopped >= 1
    assert app.destroyed == 1


def test_on_close_with_a_dead_loop_still_ends_the_session(app, monkeypatch):
    # The accept thread died (running is False) but the session is not over:
    # closing must go through the full stop, not just destroy the window.
    app.proxy.has_session, app.proxy.running = True, False
    called = threading.Event()
    monkeypatch.setattr(app, "_shutdown_and_close", called.set)
    app._on_close()
    assert called.wait(5)
    assert str(app._btn.cget("state")) == "disabled"
    assert app.destroyed == 0


def test_on_close_survives_a_failing_stop(app, monkeypatch):
    def boom():
        raise RuntimeError("stop exploded")
    monkeypatch.setattr(app.proxy, "stop", boom)
    app._on_close()
    assert app.destroyed == 1
    assert app._session_watch.stopped >= 1


@pytest.mark.parametrize("running", [False, True])
def test_ensure_stop_always_calls_stop(app, running):
    app.proxy.running = app.proxy.has_session = running
    app._ensure_stop()
    assert len(app.proxy.stops) == 1
    assert app._tray.stopped >= 1
    assert app._session_watch.stopped >= 1


def test_final_destroy_stops_the_watcher(app):
    app._final_destroy()
    assert app._session_watch.stopped >= 1
    assert app.destroyed == 1


@pytest.mark.parametrize("has_session, running, expected", [
    (True, False, "stop"),    # dead accept loop: Stop, not a doomed Start
    (True, True, "stop"),
    (False, False, "start"),
])
def test_toggle_follows_has_session(app, monkeypatch, has_session, running, expected):
    app.proxy.has_session, app.proxy.running = has_session, running
    seen = []
    done = threading.Event()
    monkeypatch.setattr(app, "_do_stop", lambda: (seen.append("stop"), done.set()))
    monkeypatch.setattr(app, "_start", lambda: (seen.append("start"), done.set()))
    app._toggle()
    assert done.wait(5)
    assert seen == [expected]


def test_unexpected_stop_flips_the_ui_to_stopped(app):
    app._start()
    assert app._btn.cget("text") == "■  Stop"
    assert app._status_text.cget("text") == "Running"
    app.proxy.has_session = app.proxy.running = False
    app.proxy.unexpected = True
    app._poll_log()
    assert app._btn.cget("text") == "▶  Start"
    assert app._status_text.cget("text") == "Stopped"
    assert str(app._rows[0].cget("state")) == "normal"


def test_log_is_drained_500_per_tick_and_capped_at_2000_lines(app):
    for i in range(3000):
        app.proxy.log_q.put(("INFO", "line %d" % i))
    app._poll_log()
    assert app.proxy.log_q.qsize() == 2500
    assert len(log_lines(app)) == 500
    for _ in range(5):
        app._poll_log()
    assert app.proxy.log_q.empty()
    lines = log_lines(app)
    assert len(lines) == 2000
    assert lines[0].endswith("line 1000")
    assert lines[-1].endswith("line 2999")


def test_verbose_log_is_capped_too(app):
    app._verbose_var.set(True)
    for i in range(2600):
        app.proxy.log_q.put(("DEBUG", "debug %d" % i))
    for _ in range(6):
        app._poll_log()
    lines = log_lines(app)
    assert len(lines) == 2000
    assert lines[-1].endswith("debug 2599")


def test_trim_log_counts_lines_not_entries(app):
    for i in range(1999):
        app._append_friendly("INFO", "entry %d" % i)
    app._trim_log()
    assert len(log_lines(app)) == 1999  # under the cap: untouched
    app._append_friendly("INFO", "two\nlines")
    app._trim_log()
    lines = log_lines(app)
    assert len(lines) == 2000
    assert lines[0].endswith("entry 1") and lines[-1] == "lines"


def test_poll_log_keeps_polling_after_an_error(app, monkeypatch):
    import sniper.ui as ui
    scheduled = []
    monkeypatch.setattr(app, "after", lambda ms, fn: scheduled.append((ms, fn)))

    def broken(level, msg):
        raise RuntimeError("formatter exploded")

    monkeypatch.setattr(ui, "friendly_format", broken)
    app.proxy.log_q.put(("INFO", "x"))
    with pytest.raises(RuntimeError):
        app._poll_log()
    assert scheduled == [(120, app._poll_log)]

