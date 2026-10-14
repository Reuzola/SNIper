"""Process identity and waiting, for the guardian (pure ctypes).

A PID alone does not name a process: Windows hands a dead process's PID to
the next one that starts. A process is named here by its PID *and* its
creation time, so the guardian can never mistake an unrelated process that
inherited a dead SNIper's PID for SNIper itself, and wait on it forever while
the proxy stays stranded.

Everything is bound on a private kernel32 WinDLL with full argtypes/restype
(handles are pointer-sized), so these bindings never leak into the shared
ctypes.windll object other modules configure. Off Windows the functions
degrade to harmless answers and the module still imports.
"""
from __future__ import annotations

import ctypes
import os

from sniper.compat import IS_WINDOWS

SYNCHRONIZE                       = 0x00100000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
WAIT_OBJECT_0    = 0x00000000
WAIT_ABANDONED_0 = 0x00000080
WAIT_TIMEOUT     = 0x00000102
WAIT_FAILED      = 0xFFFFFFFF
INFINITE         = 0xFFFFFFFF
STILL_ACTIVE     = 259
_MAXIMUM_WAIT_OBJECTS = 64

if IS_WINDOWS:
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _HANDLE = ctypes.c_void_p

    class _FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD),
                    ("dwHighDateTime", wintypes.DWORD)]

    _kernel32.GetCurrentProcess.argtypes = []
    _kernel32.GetCurrentProcess.restype = _HANDLE
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = _HANDLE
    # (hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime)
    _kernel32.GetProcessTimes.argtypes = [_HANDLE] + [ctypes.POINTER(_FILETIME)] * 4
    _kernel32.GetProcessTimes.restype = wintypes.BOOL
    _kernel32.WaitForMultipleObjects.argtypes = [
        wintypes.DWORD, ctypes.POINTER(_HANDLE), wintypes.BOOL, wintypes.DWORD]
    _kernel32.WaitForMultipleObjects.restype = wintypes.DWORD
    _kernel32.GetExitCodeProcess.argtypes = [_HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [_HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL


def _creation_time(handle):
    """The creation FILETIME of an open process handle as an int (100 ns
    ticks since 1601), or None if Windows won't say."""
    created, exited, kernel, user = (_FILETIME() for _ in range(4))
    if not _kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                     ctypes.byref(kernel), ctypes.byref(user)):
        return None
    return (created.dwHighDateTime << 32) | created.dwLowDateTime


def process_identity(pid=None):
    """(pid, creation time) of a process, the current one by default.

    The creation time is 0 when it can't be read (the process is gone, access
    is denied, or this is not Windows); 0 never matches a real process, so an
    identity that couldn't be read can't be confused with one that could.
    """
    me = os.getpid()
    pid = pid or me
    if not IS_WINDOWS:
        return pid, 0
    try:
        if pid == me:
            # A pseudo-handle: always valid, nothing to open or close.
            created = _creation_time(_kernel32.GetCurrentProcess())
        else:
            handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return pid, 0
            try:
                created = _creation_time(handle)
            finally:
                _kernel32.CloseHandle(handle)
    except Exception:
        return pid, 0
    return pid, created or 0


def open_for_wait(pid, create_time):
    """A handle to wait on the process (pid, create_time), or None if that
    process is gone or the PID now belongs to a different process (its
    creation time differs). Close the handle with close()."""
    if not IS_WINDOWS:
        return None
    try:
        handle = _kernel32.OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                       False, pid)
    except Exception:
        return None
    if not handle:
        return None
    try:
        same = _creation_time(handle) == create_time
    except Exception:
        same = False
    if not same:
        _kernel32.CloseHandle(handle)
        return None
    return handle


def wait_any(handles, timeout_ms):
    """Wait until one of handles is signaled and return its index, or None
    after timeout_ms (INFINITE waits for good). Uses no CPU while waiting.
    Raises OSError if the wait itself fails."""
    if not IS_WINDOWS:
        raise OSError("waiting on Windows handles needs Windows")
    count = len(handles)
    if not 0 < count <= _MAXIMUM_WAIT_OBJECTS:
        raise ValueError("wait_any needs 1 to %d handles, got %d"
                         % (_MAXIMUM_WAIT_OBJECTS, count))
    array = (_HANDLE * count)(*handles)
    result = _kernel32.WaitForMultipleObjects(count, array, False, timeout_ms)
    if result == WAIT_FAILED:
        raise ctypes.WinError(ctypes.get_last_error())
    if result == WAIT_TIMEOUT:
        return None
    if WAIT_OBJECT_0 <= result < WAIT_OBJECT_0 + count:
        return result - WAIT_OBJECT_0
    if WAIT_ABANDONED_0 <= result < WAIT_ABANDONED_0 + count:
        return result - WAIT_ABANDONED_0  # a mutex whose owner died: signaled too
    raise OSError("WaitForMultipleObjects returned %#x" % result)


def exit_code(handle):
    """The process's exit code (STILL_ACTIVE while it runs), or None if it
    can't be read."""
    if not IS_WINDOWS or not handle:
        return None
    code = wintypes.DWORD()
    if not _kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
        return None
    return code.value


def close(handle):
    """Close a handle from open_for_wait(); None is fine."""
    if IS_WINDOWS and handle:
        try:
            _kernel32.CloseHandle(handle)
        except Exception:
            pass
