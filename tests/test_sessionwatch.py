"""Tests for sniper.sessionwatch: the session-end message logic on any OS, and
a real hidden window on Windows.

The Windows tests send WM_QUERYENDSESSION / WM_ENDSESSION to the watcher's
own window with SendMessageW, which returns only after the window procedure
has run. The callbacks are test recorders, so no proxy setting is touched.
"""
from __future__ import annotations

import threading
import time

import pytest

import sniper.sessionwatch as sessionwatch
from helpers import wait_until
from sniper.compat import IS_WINDOWS
from sniper.sessionwatch import (WM_CLOSE, WM_DESTROY, WM_ENDSESSION,
                                 WM_QUERYENDSESSION, SessionEndWatcher,
                                 handle_session_message)

if IS_WINDOWS:
    from helpers import (WS_EX_TOOLWINDOW, is_top_level, is_window,
                         is_window_visible, send_message, window_ex_style,
                         window_thread_id)


class Calls:
    def __init__(self):
        self.log = []

    def ending(self):
        self.log.append(("ending", threading.get_ident()))

    def cancelled(self):
        self.log.append(("cancelled", threading.get_ident()))

    @property
    def names(self):
        return [name for name, _ in self.log]


def _boom():
    raise RuntimeError("callback failed")


# ── handle_session_message (any OS) ──────────────────────────────────────────
def test_query_end_session_runs_on_ending_and_never_vetoes():
    c = Calls()
    assert handle_session_message(WM_QUERYENDSESSION, 0, c.ending, c.cancelled) == 1
    assert c.names == ["ending"]


@pytest.mark.parametrize("wparam", [1, 0xFFFFFFFF])
def test_end_session_true_runs_on_ending(wparam):
    c = Calls()
    assert handle_session_message(WM_ENDSESSION, wparam, c.ending, c.cancelled) == 0
    assert c.names == ["ending"]


def test_end_session_false_runs_on_cancelled():
    c = Calls()
    assert handle_session_message(WM_ENDSESSION, 0, c.ending, c.cancelled) == 0
    assert c.names == ["cancelled"]


def test_callback_runs_before_the_function_returns():
    order = []

    def slow_callback():
        time.sleep(0.1)  # a callback merely handed off would finish later
        order.append("callback")

    handle_session_message(WM_QUERYENDSESSION, 0, slow_callback, lambda: None)
    order.append("returned")
    assert order == ["callback", "returned"]


@pytest.mark.parametrize("msg, wparam, expected", [
    (WM_QUERYENDSESSION, 0, 1), (WM_ENDSESSION, 1, 0), (WM_ENDSESSION, 0, 0)])
def test_callback_exceptions_are_swallowed(msg, wparam, expected):
    assert handle_session_message(msg, wparam, _boom, _boom) == expected


@pytest.mark.parametrize("msg", [0, WM_DESTROY, WM_CLOSE, 0x0400, 0x0015, 0x0017])
def test_other_messages_return_none(msg):
    c = Calls()
    assert handle_session_message(msg, 1, c.ending, c.cancelled) is None
    assert c.log == []


def test_watcher_is_a_no_op_off_windows(monkeypatch):
    monkeypatch.setattr(sessionwatch, "IS_WINDOWS", False)
    w = SessionEndWatcher(_boom, _boom)
    w.start()
    assert not w.ok and w.hwnd is None and w.thread is None
    w.stop()


# ── A real watcher window (Windows) ──────────────────────────────────────────
windows_integration = [
    pytest.mark.skipif(not IS_WINDOWS, reason="needs Win32 windows"),
    pytest.mark.windows_integration,
]


@pytest.fixture
def watcher():
    calls = Calls()
    w = SessionEndWatcher(calls.ending, calls.cancelled)
    w.calls = calls
    w.start()
    yield w
    w.stop()
    if w.thread is not None:
        wait_until(lambda: not w.thread.is_alive(), timeout=5)


def _win(fn):
    for mark in windows_integration:
        fn = mark(fn)
    return fn


@_win
def test_watcher_window_is_hidden_top_level(watcher):
    assert watcher.ok
    hwnd = watcher.hwnd
    assert is_window(hwnd)
    # Top-level, so it gets session-end messages (a message-only one wouldn't).
    assert is_top_level(hwnd)
    assert not is_window_visible(hwnd)
    assert window_ex_style(hwnd) & WS_EX_TOOLWINDOW
    # It belongs to the watcher's own thread, not the caller's.
    assert window_thread_id(hwnd) == watcher.thread.native_id
    assert window_thread_id(hwnd) != threading.get_native_id()


@_win
def test_query_end_session_is_handled_synchronously(watcher):
    calls = watcher.calls

    def slow_ending():
        time.sleep(0.2)  # would still be running if the call were only queued
        calls.ending()

    watcher._on_ending = slow_ending
    assert send_message(watcher.hwnd, WM_QUERYENDSESSION, 0, 0) == 1
    # Already done when SendMessageW returned, and done on the watcher thread.
    assert calls.names == ["ending"]
    assert calls.log[0][1] == watcher.thread.ident


@_win
def test_end_session_messages(watcher):
    calls = watcher.calls
    assert send_message(watcher.hwnd, WM_ENDSESSION, 0, 0) == 0
    assert calls.names == ["cancelled"]
    assert send_message(watcher.hwnd, WM_ENDSESSION, 1, 0) == 0
    assert calls.names == ["cancelled", "ending"]


@_win
def test_raising_callbacks_still_return_the_right_values(watcher):
    watcher._on_ending = _boom
    watcher._on_cancelled = _boom
    assert send_message(watcher.hwnd, WM_QUERYENDSESSION, 0, 0) == 1
    assert send_message(watcher.hwnd, WM_ENDSESSION, 1, 0) == 0
    assert send_message(watcher.hwnd, WM_ENDSESSION, 0, 0) == 0
    assert watcher.ok  # and the window survived


@_win
def test_window_procedure_never_vetoes_even_if_handling_fails(watcher, monkeypatch):
    # If the handling itself blew up, the exception would make the ctypes
    # callback return 0, a veto. The window procedure must still say 1.
    def broken(*args):
        raise RuntimeError("handler exploded")

    monkeypatch.setattr(sessionwatch, "handle_session_message", broken)
    assert send_message(watcher.hwnd, WM_QUERYENDSESSION, 0, 0) == 1
    assert send_message(watcher.hwnd, WM_ENDSESSION, 1, 0) == 0
    monkeypatch.undo()  # so WM_CLOSE can close the window at teardown


@_win
def test_stop_ends_the_thread_and_the_window(watcher):
    hwnd, thread = watcher.hwnd, watcher.thread
    watcher.stop()
    wait_until(lambda: not thread.is_alive(), timeout=5)
    assert not is_window(hwnd)
    assert not watcher.ok and watcher.hwnd is None
    watcher.stop()  # a second stop is harmless


@_win
def test_watchers_can_come_and_go():
    for _ in range(5):
        calls = Calls()
        w = SessionEndWatcher(calls.ending, calls.cancelled)
        w.start()
        assert w.ok
        assert send_message(w.hwnd, WM_QUERYENDSESSION, 0, 0) == 1
        w.stop()
        wait_until(lambda: not w.thread.is_alive(), timeout=5)
        assert calls.names == ["ending"]


@_win
def test_stop_before_start_and_start_twice():
    calls = Calls()
    w = SessionEndWatcher(calls.ending, calls.cancelled)
    w.stop()  # never started: nothing to do
    w.start()
    first = w.thread
    w.start()  # already running: ignored
    assert w.thread is first
    w.stop()
    wait_until(lambda: not first.is_alive(), timeout=5)
