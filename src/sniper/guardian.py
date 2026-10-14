"""The guardian: a small separate process that restores the system proxy the
moment SNIper dies, and says so.

Safe mode already makes a dead SNIper harmless for most apps, and the next
launch cleans up in any case. The guardian removes even the harmless
leftover at once, fixes long-running apps that cached the PAC script, and is
the main protection for Compatibility mode. Nothing can catch a Task Manager
kill from inside the process being killed, so it has to be another process.

How it gets there. When SNIper applies the system proxy it starts an
*intermediate* process (--spawn-guard), which starts the guardian (--guard)
and exits at once. The guardian's parent is then gone, so "End process tree"
or taskkill /T on SNIper does not reach it. A kill in the first second or
two, while the intermediate still lives, can take both down; safe mode and
launch recovery still cover that.

What it does. It waits, using no CPU, on SNIper's process handle and on
change notifications for HKCU\\Software\\SNIper:
- SNIper's process ends: it runs the normal winproxy.proxy_restore() for its
  own session only, and if that restored something, shows a notification;
- the record goes away or names a newer session (a clean Stop, a sign-out,
  a re-apply): it leaves quietly, having nothing left to guard.
The owner is named by its PID *and* creation time, so a PID that Windows
hands to another process is never mistaken for SNIper.

Every child gets PYINSTALLER_RESET_ENVIRONMENT=1. Without it a frozen child
reuses its parent's _MEI unpack directory, which PyInstaller deletes when the
parent (SNIper) dies: the exact moment the guardian is needed.

The guard path never imports tkinter, sniper.ui, sniper.proxy or sniper.dns,
and never prints (a frozen windowed process has no stdout). The self-test
owner (--selftest-owner) is for tests only: it runs a real ProxyServer and
refuses to start unless winproxy is pointed at a test sandbox.
"""
from __future__ import annotations

import ctypes
import os
import re
import subprocess
import sys
import threading
import time

from sniper import procutil, winproxy
from sniper.compat import IS_WINDOWS, winreg

# The process modes, as the first command-line argument. The entry points
# check for these literally, before importing anything else.
GUARD          = "--guard"
SPAWN_GUARD    = "--spawn-guard"
SELFTEST_OWNER = "--selftest-owner"
MODES = (GUARD, SPAWN_GUARD, SELFTEST_OWNER)

# Exit codes (tests and the frozen-EXE checks read them).
EXIT_NOTHING  = 0    # nothing to do: clean stop, record gone, newer session
EXIT_BAD_ARGS = 2
EXIT_ERROR    = 3    # unexpected error; a final restore was still attempted
EXIT_RESTORED = 10
EXIT_KEPT     = 11
EXIT_ALREADY  = 12
EXIT_NOT_OURS = 13
_OUTCOME_EXIT = {
    "restored": EXIT_RESTORED,
    "kept":     EXIT_KEPT,
    "already":  EXIT_ALREADY,
    "not-ours": EXIT_NOT_OURS,
    None:       EXIT_NOTHING,   # no record left: someone else finished it
}

NOTICE = "SNIper closed unexpectedly. Your internet settings were restored automatically."
_NOTIFY_ENV = "SNIPER_GUARD_NOTIFY"   # "0" turns the notification off (tests)
_NOTIFY_SECONDS = 8.0

# Creation flags: no console, its own process group (so a console Ctrl+C or
# Ctrl+Break aimed at SNIper's group never reaches it), and out of SNIper's
# job object if there is one, so closing the job does not kill it.
_DETACHED_PROCESS          = 0x00000008
_CREATE_NEW_PROCESS_GROUP  = 0x00000200
_CREATE_BREAKAWAY_FROM_JOB = 0x01000000
_REAP_TIMEOUT = 120   # seconds a reaper thread waits for a launched child

_SESSION_RX = re.compile(r"[0-9a-f]{16}")
_NUMBER_RX = re.compile(r"[0-9]{1,20}")

# Waiting: what woke the guardian up, and how often to look at the record
# when change notifications are not available.
_OWNER, _RECORD = "owner", "record"
_POLL_MS = 2000
_REG_NOTIFY_CHANGE_NAME     = 0x00000001
_REG_NOTIFY_CHANGE_LAST_SET = 0x00000004

if IS_WINDOWS:
    from ctypes import wintypes

    # Private DLL objects: these bindings never leak into ctypes.windll.
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL,
                                       wintypes.LPCWSTR]
    _kernel32.CreateEventW.restype = ctypes.c_void_p  # HANDLE
    _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    # (HKEY hKey, BOOL bWatchSubtree, DWORD dwNotifyFilter, HANDLE hEvent,
    #  BOOL fAsynchronous) -> LSTATUS
    _advapi32.RegNotifyChangeKeyValue.argtypes = [
        ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.BOOL]
    _advapi32.RegNotifyChangeKeyValue.restype = wintypes.LONG


# ── Launching ────────────────────────────────────────────────────────────────
def _package_parent():
    """The directory that holds the sniper package (src/ from source)."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _base_cmd():
    """How to start this program again: the EXE itself when frozen, else
    this interpreter running the package."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, "-m", "sniper"]


def _child_env():
    """The environment for a child: ours, plus PYINSTALLER_RESET_ENVIRONMENT
    (a frozen child unpacks to its own _MEI directory, which outlives
    SNIper's) and, from source, the package's directory on PYTHONPATH."""
    env = dict(os.environ)
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    if not getattr(sys, "frozen", False):
        old = env.get("PYTHONPATH")
        env["PYTHONPATH"] = _package_parent() + (os.pathsep + old if old else "")
    return env


def _reap(proc):
    try:
        proc.wait(timeout=_REAP_TIMEOUT)
    except Exception:
        pass


def _launch_detached(args):
    """Start this program with args, detached; True if it started.

    Breaking away from a job object is refused by a job that doesn't allow
    it (CreateProcess fails), so that is retried without the flag: a guardian
    inside SNIper's job still covers every kill but the job's own end. The
    child is reaped from a daemon thread, so no ResourceWarning fires."""
    cmd = _base_cmd() + [str(a) for a in args]
    env = _child_env()
    base = _DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP
    for flags in (base | _CREATE_BREAKAWAY_FROM_JOB, base):
        try:
            proc = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL,
                                    close_fds=True, creationflags=flags)
        except OSError:
            continue
        try:
            threading.Thread(target=_reap, args=(proc,), daemon=True).start()
        except Exception:
            pass
        return True
    return False


def _parse_owner(args):
    """(pid, creation time, session id) from the three command-line
    arguments, or None if they are not exactly that. A creation time of 0
    means "unknown" and is refused: with it, a live owner could not be told
    from a dead one."""
    if len(args) != 3:
        return None
    pid, created, session = args
    if not (_NUMBER_RX.fullmatch(pid) and _NUMBER_RX.fullmatch(created)
            and _SESSION_RX.fullmatch(session)):
        return None
    pid, created = int(pid), int(created)
    if not (0 < pid <= 0xFFFFFFFF and 0 < created <= 0xFFFFFFFFFFFFFFFF):
        return None
    return pid, created, session


def spawn_guardian(session_id):
    """Start the guardian for the current process's session (owner side).
    True if the intermediate process started. Never raises."""
    if not IS_WINDOWS:
        return False
    try:
        if not _SESSION_RX.fullmatch(session_id or ""):
            return False
        pid, created = procutil.process_identity()
        if not created:
            # This process can't be told apart from one that later gets its
            # PID, so a guardian could take a live SNIper for a dead one and
            # undo its proxy. No guardian is the safer side.
            return False
        return _launch_detached([SPAWN_GUARD, pid, created, session_id])
    except Exception:
        return False


def run_spawn_guard(args):
    """The intermediate: start the guardian with the same arguments and exit
    at once, so the guardian has no parent in SNIper's process tree."""
    owner = _parse_owner(args)
    if owner is None:
        return EXIT_BAD_ARGS
    try:
        started = _launch_detached([GUARD] + [str(x) for x in owner])
    except Exception:
        started = False
    return EXIT_NOTHING if started else EXIT_ERROR


# ── The guardian ─────────────────────────────────────────────────────────────
class _Win32Waiter:
    """The guardian's waits, on Win32: the owner's process handle, and a
    change notification on HKCU\\<winproxy._SNIPER_KEY> (the whole subtree,
    so the record's deletion, a rewrite, or its parent's removal all count).
    run_guardian takes any object with these four methods, so the logic can
    be tested without Win32."""

    def __init__(self):
        self._key = None      # winreg handle, open while notifications are armed
        self._event = None    # auto-reset event the notification signals

    def open_owner(self, pid, created):
        return procutil.open_for_wait(pid, created)

    def arm(self):
        """Register for the next change; False if that is not possible (no
        key at all, or any failure), and the caller polls instead."""
        try:
            if self._key is None:
                self._key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                           winproxy._SNIPER_KEY, 0, winreg.KEY_NOTIFY)
            if self._event is None:
                self._event = _kernel32.CreateEventW(None, False, False, None) or None
                if self._event is None:
                    return False
            status = _advapi32.RegNotifyChangeKeyValue(
                int(self._key), True,
                _REG_NOTIFY_CHANGE_NAME | _REG_NOTIFY_CHANGE_LAST_SET,
                self._event, True)
            return status == 0
        except Exception:
            return False

    def wait(self, owner, armed):
        """_OWNER or _RECORD for what was signaled, or None after a polling
        interval when notifications are not armed."""
        if armed:
            index = procutil.wait_any([owner, self._event], procutil.INFINITE)
            return _OWNER if index == 0 else _RECORD
        return _OWNER if procutil.wait_any([owner], _POLL_MS) == 0 else None

    def close(self, owner):
        procutil.close(owner)
        if self._event is not None:
            try:
                _kernel32.CloseHandle(self._event)
            except Exception:
                pass
            self._event = None
        if self._key is not None:
            try:
                winreg.CloseKey(self._key)
            except Exception:
                pass
            self._key = None


def _owner_died(pid, created, session, waiter, read_session):
    """Block until the owner process ends (True) or its session ends cleanly
    (False: no complete record any more, or one of a newer session)."""
    owner = waiter.open_owner(pid, created)
    if owner is None:
        return True  # already gone (or its PID reused) before we got here
    try:
        armed = waiter.arm()
        while True:
            # Checked after every (re-)arm, so a change landing between this
            # check and the wait still wakes the wait up.
            if read_session() != session:
                return False
            try:
                woke = waiter.wait(owner, armed)
            except OSError:
                if not armed:
                    raise  # even the plain wait on the owner failed
                armed = False  # notifications broke: poll the record instead
                continue
            if woke == _OWNER:
                return True
            if woke == _RECORD:
                armed = waiter.arm()
    finally:
        waiter.close(owner)


def run_guardian(args, waiter=None, read_session=None):
    """The guardian process. args: owner pid, owner creation time, session
    id. Returns one of the EXIT_* codes; see the module docstring.

    waiter and read_session default to Win32 and winproxy.current_session_id;
    tests pass fakes."""
    owner = _parse_owner(args)
    if owner is None:
        return EXIT_BAD_ARGS
    pid, created, session = owner
    try:
        if waiter is None:
            waiter = _Win32Waiter()
        if read_session is None:
            read_session = winproxy.current_session_id
        if not _owner_died(pid, created, session, waiter, read_session):
            return EXIT_NOTHING
        result = winproxy.proxy_restore(session_id=session)
    except Exception:
        # Something unforeseen: still try to put the proxy back before
        # leaving, as the next launch would (for this session only).
        try:
            winproxy.proxy_restore(session_id=session)
        except Exception:
            pass
        return EXIT_ERROR
    if result == "restored" and os.environ.get(_NOTIFY_ENV) != "0":
        notify_restored()
    return _OUTCOME_EXIT.get(result, EXIT_ERROR)


# ── The notification ─────────────────────────────────────────────────────────
_NIF_MESSAGE, _NIF_ICON, _NIF_TIP, _NIF_INFO = 0x1, 0x2, 0x4, 0x10
_NIM_ADD, _NIM_DELETE = 0, 2
_NIIF_INFO = 0x1
_PM_REMOVE = 0x0001


def _shell_notify(message, nid):
    """Shell_NotifyIconW (sniper.tray binds it); tests replace this."""
    from sniper import tray
    return tray._shell32.Shell_NotifyIconW(message, ctypes.byref(nid))


def _bind_notice_calls(user32):
    """The user32 calls the notification needs beyond what sniper.tray
    binds, with their real types."""
    from sniper.tray import _MSG
    user32.PeekMessageW.argtypes = [ctypes.POINTER(_MSG), wintypes.HWND,
                                    wintypes.UINT, wintypes.UINT, wintypes.UINT]
    user32.PeekMessageW.restype = wintypes.BOOL
    user32.DestroyWindow.argtypes = [wintypes.HWND]
    user32.DestroyWindow.restype = wintypes.BOOL
    user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
    user32.UnregisterClassW.restype = wintypes.BOOL


def notify_restored(seconds=_NOTIFY_SECONDS):
    """Show "SNIper closed unexpectedly…" as a Windows notification from a
    temporary tray icon, keep it for about seconds, then remove the icon.
    True if it was shown. Never raises: a failure is silent."""
    if not IS_WINDOWS:
        return False
    try:
        return _show_notice(seconds)
    except Exception:
        return False


def _show_notice(seconds):
    from sniper import tray  # lazily: only a guardian that restored needs it
    user32 = tray._user32
    _bind_notice_calls(user32)
    hinst = tray._kernel32.GetModuleHandleW(None)
    cls_name = "SNIperGuardNotice_%d" % os.getpid()

    def wndproc(hwnd, msg, wparam, lparam):
        try:
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)
        except Exception:
            return 0

    # Referenced until this function returns, after the window and its class
    # are gone: a collected callback would crash the window procedure.
    wndproc_ref = tray._WNDPROC(wndproc)
    wc = tray._WNDCLASSW()
    wc.lpfnWndProc = wndproc_ref
    wc.hInstance = hinst
    wc.lpszClassName = cls_name
    if not user32.RegisterClassW(ctypes.byref(wc)):
        return False
    try:
        # A hidden top-level window owns the icon (as in sniper.tray).
        hwnd = user32.CreateWindowExW(tray._WS_EX_TOOLWINDOW, cls_name, "SNIper", 0,
                                      0, 0, 0, 0, None, None, hinst, None)
        if not hwnd:
            return False
        try:
            nid = tray._NOTIFYICONDATAW()
            nid.cbSize = ctypes.sizeof(tray._NOTIFYICONDATAW)
            nid.hWnd = hwnd
            nid.uID = 1
            nid.uFlags = _NIF_MESSAGE | _NIF_ICON | _NIF_TIP | _NIF_INFO
            nid.uCallbackMessage = tray._WM_TRAY_CB
            nid.hIcon = tray._tray_hicon()
            nid.szTip = "SNIper"
            nid.szInfoTitle = "SNIper"
            nid.szInfo = NOTICE
            nid.dwInfoFlags = _NIIF_INFO
            if not _shell_notify(_NIM_ADD, nid):
                return False
            try:
                _pump_messages(user32, seconds)
            finally:
                _shell_notify(_NIM_DELETE, nid)
            return True
        finally:
            user32.DestroyWindow(hwnd)
    finally:
        user32.UnregisterClassW(cls_name, hinst)


def _pump_messages(user32, seconds):
    """Keep the notification window responsive for seconds."""
    from sniper.tray import _MSG
    msg = _MSG()
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        while user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, _PM_REMOVE):
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        time.sleep(0.05)


# ── Self-test owner (tests only) ─────────────────────────────────────────────
def _parse_selftest(args):
    """(mode, stop_after seconds or None), or None for bad arguments."""
    if not args or args[0] not in ("safe", "compat"):
        return None
    if len(args) == 1:
        return args[0], None
    if len(args) == 3 and args[1] == "--stop-after":
        try:
            seconds = float(args[2])
        except ValueError:
            return None
        if 0 <= seconds <= 3600:
            return args[0], seconds
    return None


def _write_selftest(values):
    """Write (name, (data, type)) pairs to <sandbox>\\SelfTest, in order."""
    k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, winproxy._SANDBOX_ROOT + r"\SelfTest")
    try:
        for name, (data, kind) in values:
            winreg.SetValueEx(k, name, 0, kind, data)
    finally:
        winreg.CloseKey(k)


def run_selftest_owner(args):
    """A stand-in SNIper for tests: a real ProxyServer session ("safe" or
    "compat"), reported in <sandbox>\\SelfTest (OwnerPid, Port, SessionId,
    then Ready=1 last). With --stop-after N it stops cleanly after N seconds
    and writes Stopped=1; otherwise it runs until killed.

    Refuses (EXIT_ERROR) unless winproxy runs in a valid test sandbox, so it
    can never touch the real proxy settings."""
    if not winproxy._SANDBOXED:
        return EXIT_ERROR
    parsed = _parse_selftest(args)
    if parsed is None:
        return EXIT_BAD_ARGS
    mode, stop_after = parsed
    from sniper.server import ProxyServer  # the owner side, never the guard path
    server = ProxyServer()
    try:
        server.start(0, 2, use_doh=False, compat=(mode == "compat"))
    except Exception:
        return EXIT_ERROR
    _write_selftest([("OwnerPid", (os.getpid(), winreg.REG_DWORD)),
                     ("Port", (server.port, winreg.REG_DWORD)),
                     ("SessionId", (server.session_id or "", winreg.REG_SZ)),
                     ("Ready", (1, winreg.REG_DWORD))])
    if stop_after is None:
        while True:
            time.sleep(3600)
    time.sleep(stop_after)
    server.stop()
    _write_selftest([("Stopped", (1, winreg.REG_DWORD))])
    return EXIT_NOTHING


# ── Dispatch ─────────────────────────────────────────────────────────────────
def dispatch(argv):
    """Run the process mode named by argv[0] with the rest as its arguments
    and return the exit code. Unknown modes are bad arguments. Never raises:
    in a frozen windowed EXE an uncaught exception would show a dialog."""
    if not argv:
        return EXIT_BAD_ARGS
    handler = {GUARD: run_guardian, SPAWN_GUARD: run_spawn_guard,
               SELFTEST_OWNER: run_selftest_owner}.get(argv[0])
    if handler is None:
        return EXIT_BAD_ARGS
    try:
        return handler(list(argv[1:]))
    except Exception:
        return EXIT_ERROR
