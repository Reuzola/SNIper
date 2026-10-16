"""Windows system-proxy registry management.

SNIper points the per-user system proxy at itself in one of two modes:

- Safe mode ("pac", the default): AutoConfigURL names a PAC script SNIper
  serves itself (see sniper.pac), and next to it a manual proxy that bypasses
  every host: ProxyEnable=1, ProxyServer=127.0.0.1:port, ProxyOverride="*".
  A dead SNIper is then harmless with no code having to run: the script can't
  be fetched, or the proxy it names refuses, and clients go DIRECT. WinINet
  and Chromium fall back from a failed auto-config script to the manual
  proxy, and its bypass list sends every host DIRECT; without that list the
  fallback would be the dead SNIper.
  The manual proxy is there for apps that read only ProxyEnable/ProxyServer
  and ignore both the script and the bypass list. The Discord desktop app's
  updater (Rust reqwest 0.11) is one: it reads them once when Discord starts,
  and can't reach updates.discord.com without them, so Discord never opens.
  Only such apps lose their connection if SNIper dies (until the guardian
  restores); everything that follows the script or the bypass list fails open.
- Compatibility mode ("static"): ProxyEnable=1 and ProxyServer=127.0.0.1:port,
  for apps that ignore PAC scripts. This is exactly the v1.1.7 behavior.

The genuine pre-SNIper proxy configuration (the *restore baseline*) is written
to a durable per-user registry key BEFORE SNIper overwrites the live Internet
Settings values, and the commit marker is written last. This makes the restore
crash-durable: a graceful exit restores immediately, while an ungraceful one
(force kill, power loss, OS logoff/shutdown) leaves the baseline behind so the
next launch self-heals via recover_orphaned_proxy().

Both sides are footprint-aware. Capture (proxy_enable) never records SNIper's
own leftover state as the baseline, and refuses outright, writing nothing, when
a live value is one the record couldn't put back exactly. Restore
(proxy_restore, and the launch self-heal it backs) writes the genuine baseline
back ONLY when the live proxy is still exactly the footprint SNIper applied,
all remembered durably: in static mode the enable flag, the server address and
the PAC-cleared state; in safe mode the script URL, which holds a random value
per session, so it is provably SNIper's own, and the manual proxy values. If
the live proxy has diverged — the user changed it during the
session or between a crash and the next launch — SNIper treats the user as
having taken control: it leaves the live proxy untouched and simply drops the
durable record. SNIper only ever undoes its own change, never a manual one —
and never by guessing from the loopback address. In safe mode the script URL
and the manual proxy are judged apart: SNIper's one-off script URL is always
removed while it is still there, and the manual proxy is put back unless the
user changed any of its values.

The record names the mode it was written for (AppliedMode). A record without
it was written by v1.1.7 and is static; one without AppliedProxyServer
predates footprints. Both are recovered exactly as before. A safe-mode record
without AppliedManualProxy comes from a v1.2.0 build before the manual proxy
was added, whose footprint was the script URL and ProxyEnable=0.

Every record also names its owner: the process that applied it (OwnerPid and
OwnerCreateTime, which together name one process even after Windows reuses
the PID) and a random SessionId per apply. The guardian (sniper.guardian), a
separate process that restores the moment SNIper dies, passes its session to
proxy_restore() and so only ever restores the session it was started for; a
record that belongs to a newer session is "not-ours". Launch recovery and
SNIper's own Stop pass no session and restore whatever record there is.

More than one process can now act on the record (SNIper, its guardian), so
every read-decide-write sequence runs under a session-local named mutex.

Compatibility mode has one more net, for when SNIper and its guardian both
die or the EXE is gone: a one-time RunOnce entry that puts the genuine values
back at the next sign-in with Windows' own reg.exe (see _write_runonce). Safe
mode never writes it: its footprint already fails open for everything that
follows the script or the bypass list, and the few apps that read only the
manual proxy stay offline until the next launch recovers the record.

All operations stay HKCU-only (no admin), standard-library only, and guarded so
the module still imports on a non-Windows host where winreg is None.
"""
from __future__ import annotations

import contextlib
import ctypes
import os
import re
import secrets
from collections import namedtuple

from sniper import procutil
from sniper.compat import IS_WINDOWS, winreg

_IE        = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_IE_POLICY = r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"

# Durable per-user store for the restore baseline. It exists EXACTLY while
# SNIper holds the proxy modified with an un-restored baseline: written before
# the live overwrite, deleted after a successful restore OR a back-off. Holds
# both the genuine pre-SNIper config and the footprint SNIper applied, so the
# "is the live proxy still mine?" check works in the graceful and post-crash
# paths alike. Registry-only, never the filesystem.
_SNIPER_KEY  = r"Software\SNIper"
_RESTORE_KEY = r"Software\SNIper\ProxyRestore"

# Serializes every read-decide-write of the record across processes (SNIper,
# its guardian). Session-local like the single-instance mutex: no "Global\".
_STATE_MUTEX_NAME = "SNIper_proxy_state"

# ── Compatibility-mode safety net: RunOnce ────────────────────────────────────
# After a static (Compatibility-mode) apply, one RunOnce value per genuine
# value holds a complete reg.exe command that writes it back. If SNIper and
# its guardian both die (power loss, both killed, the EXE deleted), Windows
# runs them at the next sign-in and the static proxy is gone without SNIper
# ever running again. Windows deletes a RunOnce value before it runs it, so
# nothing is left once it has fired. It is a blind restore of the genuine
# values: it can't check a footprint, so it is removed whenever the record is
# cleared, on every safe-mode apply and on every launch recovery, and it only
# ever fires after an unclean exit in Compatibility mode. reg.exe is a console
# program, so a console window may flash briefly at that sign-in.
# RUNONCE_SAFETY_NET is the kill switch: when False nothing is ever written,
# while stale values are still removed wherever they would be.
RUNONCE_SAFETY_NET = True
_RUNONCE = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
_RUNONCE_PREFIX = "SNIperRestore"
_RUNONCE_MAX_CHARS = 260  # the documented limit for Run/RunOnce data

# ── Test sandbox for subprocesses ─────────────────────────────────────────────
# Tests run the guardian and a self-test owner as real subprocesses, which no
# monkeypatch reaches, so they name a throwaway registry tree in this variable
# instead. It is honored only for the exact shape the test fixture creates;
# any other value (a real key, a short id, a path with "..", an empty string)
# is ignored entirely and the real keys are used. In a sandbox the WinINet
# refresh and the Group Policy check are off, as in the in-process fixture,
# and the mutex is the sandbox's own, so tests never contend with a real
# SNIper. RunOnce is redirected too: a plain key Windows never runs. The
# settings key is not redirected: no sandboxed code path uses it.
_SANDBOX_ENV = "SNIPER_REGISTRY_SANDBOX"
_SANDBOX_RX = re.compile(r"Software\\SNIper-pytest-([0-9a-f]{32})")


def _sandbox_root(value):
    """value if it is exactly Software\\SNIper-pytest-<32 lowercase hex>,
    else None. fullmatch, so not even a trailing newline gets through."""
    m = _SANDBOX_RX.fullmatch(value or "")
    return m.group(0) if m else None


_SANDBOX_ROOT = _sandbox_root(os.environ.get(_SANDBOX_ENV))
_SANDBOXED = _SANDBOX_ROOT is not None
if _SANDBOXED:
    _IE = _SANDBOX_ROOT + r"\Internet Settings"
    _SNIPER_KEY = _SANDBOX_ROOT + r"\SNIper"
    _RESTORE_KEY = _SNIPER_KEY + r"\ProxyRestore"
    _RUNONCE = _SANDBOX_ROOT + r"\RunOnce"
    _STATE_MUTEX_NAME = "SNIper_proxy_state_" + _SANDBOX_RX.fullmatch(_SANDBOX_ROOT).group(1)

# The AppliedMode values. Anything else in a record (a missing value, or one
# from some future version) reads as static, whose exact footprint check then
# decides; at worst that leaves the live proxy alone.
MODE_STATIC = "static"
MODE_PAC    = "pac"

# The bypass list of safe mode's manual proxy: every host. WinINet, WinHTTP,
# Chromium and Python all read "*" as matching any host name.
_BYPASS_ALL = "*"

# A complete restore record, as _read_baseline returns it:
#   enable, server        the genuine ProxyEnable / ProxyServer
#   pac_present, pac      whether a genuine AutoConfigURL existed, and its value
#   applied_server        the address SNIper applied; None in a legacy record
#   applied_mode          MODE_PAC or MODE_STATIC
#   applied_pac_url       the script URL SNIper applied in PAC mode, else None
#   owner_pid             the process that applied it, and its creation
#   owner_create_time     time (FILETIME as an int); None in older records
#   session_id            16 hex digits, new for every apply; None in older
#                         records
#   override_present,     whether a genuine ProxyOverride existed, and its
#   override              value; override_present is None when the record
#                         doesn't hold it (no footprint but safe mode's manual
#                         proxy ever wrote it)
#   applied_manual        True if SNIper applied safe mode's manual proxy
#                         (ProxyEnable=1, ProxyServer=applied_server,
#                         ProxyOverride="*") next to its script URL
Baseline = namedtuple("Baseline", "enable server pac_present pac applied_server "
                                  "applied_mode applied_pac_url owner_pid "
                                  "owner_create_time session_id "
                                  "override_present override applied_manual",
                      defaults=(None, None, False))


class UnrecordableProxyValue(ValueError):
    """proxy_enable refused, having written nothing, because a live proxy
    value can't be recorded so that a restore puts it back exactly. The
    message names the value and is fit to show the user."""


# WinINet options that make running clients pick up changed proxy settings.
_INTERNET_OPTION_REFRESH          = 37
_INTERNET_OPTION_SETTINGS_CHANGED = 39
_internet_set_option = None  # InternetSetOptionW, bound on first use

# The state mutex: how long to wait for it, and the waits' results.
_STATE_LOCK_TIMEOUT_MS = 5000
_WAIT_OBJECT_0  = 0x00000000
_WAIT_ABANDONED = 0x00000080
_mutex_api = None  # a private kernel32 with the four calls bound, on first use


def _bind_mutex_api():
    """kernel32 with CreateMutexW, WaitForSingleObject, ReleaseMutex and
    CloseHandle bound to their real (pointer-sized handle) types, on a
    private WinDLL so the bindings never leak into ctypes.windll."""
    global _mutex_api
    if _mutex_api is None:
        from ctypes import wintypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        k.CreateMutexW.restype = ctypes.c_void_p  # HANDLE
        k.WaitForSingleObject.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        k.WaitForSingleObject.restype = wintypes.DWORD
        k.ReleaseMutex.argtypes = [ctypes.c_void_p]
        k.ReleaseMutex.restype = wintypes.BOOL
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        k.CloseHandle.restype = wintypes.BOOL
        _mutex_api = k
    return _mutex_api


@contextlib.contextmanager
def _state_lock():
    """Hold the cross-process state mutex for one read-decide-write of the
    record; yields whether it was acquired.

    WAIT_ABANDONED counts as acquired: the previous holder was killed in the
    middle of an operation, and the Complete marker keeps the record
    consistent whatever it left behind. After _STATE_LOCK_TIMEOUT_MS, or if
    the mutex can't be created at all, the operation goes ahead without it:
    restoring late, or unserialized, beats not restoring. A mutex belongs to
    the thread that took it, so it is always released on that same thread.
    No-op off Windows.
    """
    k = handle = None
    acquired = False
    if IS_WINDOWS:
        try:
            k = _bind_mutex_api()
            handle = k.CreateMutexW(None, False, _STATE_MUTEX_NAME)
            if handle:
                acquired = k.WaitForSingleObject(handle, _STATE_LOCK_TIMEOUT_MS) in (
                    _WAIT_OBJECT_0, _WAIT_ABANDONED)
        except Exception:
            pass
    try:
        yield acquired
    finally:
        if acquired:
            try:
                k.ReleaseMutex(handle)
            except Exception:
                pass
        if handle:
            try:
                k.CloseHandle(handle)
            except Exception:
                pass


def _proxy_gpo_locked():
    """True if Group Policy disables per-user proxy settings.

    When HKLM ...\\Internet Settings\\ProxySettingsPerUser is 0, Windows
    ignores the per-user (HKCU) proxy values this program writes — the write
    succeeds but has no effect. Detecting it lets us warn the user instead of
    failing silently on a managed/corporate machine. Always False in a test
    sandbox, whose keys no policy governs.
    """
    if not IS_WINDOWS or _SANDBOXED:
        return False
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _IE_POLICY)
        try:
            val = winreg.QueryValueEx(k, "ProxySettingsPerUser")[0]
        finally:
            winreg.CloseKey(k)
        return val == 0
    except OSError:
        return False


def _bind_internet_set_option():
    """InternetSetOptionW with its real argument types. HINTERNET is
    pointer-sized: an unbound call would pass the NULL handle as a 32-bit
    int. A private WinDLL, so the binding never leaks into the shared
    ctypes.windll.wininet."""
    global _internet_set_option
    if _internet_set_option is None:
        fn = ctypes.WinDLL("wininet").InternetSetOptionW
        # (HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength)
        fn.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong]
        fn.restype = ctypes.c_int  # BOOL
        _internet_set_option = fn
    return _internet_set_option


def _refresh():
    """Tell running WinINet clients the proxy settings changed and have them
    re-read them, so an apply or a restore takes effect at once. Not in a
    test sandbox: it would make every client reload the real settings."""
    if not IS_WINDOWS or _SANDBOXED:
        return
    try:
        set_option = _bind_internet_set_option()
        set_option(None, _INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
        set_option(None, _INTERNET_OPTION_REFRESH, None, 0)
    except Exception:
        pass


# ── Live HKCU Internet Settings ────────────────────────────────────────────────
def _read_live():
    """Return (ProxyEnable, ProxyServer, AutoConfigURL) from the live HKCU
    Internet Settings. AutoConfigURL is None when the value is absent (so a
    restore can leave it absent rather than create an empty value)."""
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE, 0, winreg.KEY_READ)
    try:
        try:
            e = winreg.QueryValueEx(k, "ProxyEnable")[0]
        except FileNotFoundError:
            e = 0
        try:
            s = winreg.QueryValueEx(k, "ProxyServer")[0]
        except FileNotFoundError:
            s = ""
        try:
            a = winreg.QueryValueEx(k, "AutoConfigURL")[0]
        except FileNotFoundError:
            a = None
        return e, s, a
    finally:
        winreg.CloseKey(k)


def _read_override():
    """The live HKCU ProxyOverride (the manual proxy's bypass list), or None
    when the value is absent."""
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE, 0, winreg.KEY_READ)
    try:
        try:
            return winreg.QueryValueEx(k, "ProxyOverride")[0]
        except FileNotFoundError:
            return None
    finally:
        winreg.CloseKey(k)


def _apply_live(addr, clear_pac):
    """Point the live HKCU proxy at addr. Only ever runs AFTER the durable
    baseline is committed, so the genuine state is already recoverable. The
    PAC script is cleared only when the genuine baseline actually had one
    (Windows evaluates a PAC before the static ProxyServer, so a PAC returning
    DIRECT would bypass us); the genuine PAC lives in the durable baseline and
    is put back on restore."""
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE, 0, winreg.KEY_WRITE)
    try:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, addr)
        if clear_pac:
            winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ, "")
    finally:
        winreg.CloseKey(k)


def _apply_live_pac(pac_url, addr):
    """Point the live HKCU proxy at SNIper in safe mode: its PAC script, and
    the manual proxy that bypasses every host. Like _apply_live, only ever
    runs AFTER the durable baseline is committed.

    The bypass list goes in first and the enable flag last, so no moment
    ever has a manual proxy enabled that doesn't bypass every host: wherever
    an interruption stops it, a dead SNIper still fails open. Each value
    written is either the genuine one or exactly SNIper's, both in the
    record, so the restore recognizes and fully undoes any such state."""
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE, 0, winreg.KEY_WRITE)
    try:
        winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, _BYPASS_ALL)
        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, addr)
        winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    finally:
        winreg.CloseKey(k)


def _write_live_genuine(enable, server, pac_present, pac):
    """Write the genuine pre-SNIper values back to the live HKCU proxy,
    removing SNIper's footprint entirely (a genuinely-absent PAC is deleted, not
    left as the empty value SNIper used while running)."""
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE, 0, winreg.KEY_WRITE)
    try:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, int(enable))
        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, server or "")
        if pac_present:
            winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ, pac or "")
        else:
            try:
                winreg.DeleteValue(k, "AutoConfigURL")
            except OSError:
                pass
    finally:
        winreg.CloseKey(k)


def _write_live_pac_genuine(manual, script):
    """Undo safe mode on the live HKCU proxy. manual lists (value name,
    genuine value) for the manual proxy values that are still SNIper's,
    written in that order, None meaning the value didn't exist; script is
    (pac_present, pac) to put the genuine script back (or remove ours if
    there was none), or None to leave AutoConfigURL alone.

    The script goes last, so an interruption leaves our URL in place for the
    next restore to find and finish. Only a missing value is ignored when
    deleting; any other failure is an error that keeps the record for a
    retry."""
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE, 0, winreg.KEY_WRITE)
    try:
        for name, value in manual:
            if name == "ProxyEnable":
                winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(value))
            elif value is None:
                try:
                    winreg.DeleteValue(k, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)
        if script is not None:
            pac_present, pac = script
            if pac_present:
                winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ, pac or "")
            else:
                try:
                    winreg.DeleteValue(k, "AutoConfigURL")
                except FileNotFoundError:
                    pass
    finally:
        winreg.CloseKey(k)


def _flag(value):
    """A ProxyEnable value as the REG_DWORD number it holds, or None when it
    can't be read as one: a REG_SZ such as "x", REG_BINARY bytes, or a number
    outside the DWORD range. SNIper only ever writes REG_DWORDs, so None is
    never a value of SNIper's, and never one it can write back."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if 0 <= n <= 0xFFFFFFFF else None


def _is_footprint(live, applied_server, pac_present):
    """True if the live proxy is still EXACTLY what SNIper applied: enabled,
    pointed at the remembered server address, with the PAC in the state SNIper
    left it (emptied when there was a genuine PAC, absent otherwise). An exact
    match against what SNIper actually applied — never a guess from the loopback
    address — so a manual change of any of these fields reads as 'not mine'.
    So does an enable flag that can't be read as a number: it isn't the 1
    SNIper wrote, and SNIper never overwrites a value it can't interpret."""
    live_e, live_s, live_a = live
    if _flag(live_e) != 1:
        return False
    if (live_s or "") != applied_server:
        return False
    if pac_present:
        # SNIper had cleared a genuine PAC to the empty string while running.
        if live_a != "":
            return False
    else:
        # SNIper never touched AutoConfigURL, so it must still be absent.
        if live_a is not None:
            return False
    return True


def _is_genuine(live, base):
    """True if the live proxy already IS the genuine pre-SNIper config the
    record holds: the same enable flag, server and PAC (an absent PAC stays
    distinct from an empty one). Someone else put it back before us: the
    guardian, a restore in another process, or the user by hand."""
    live_e, live_s, live_a = live
    try:
        if int(live_e or 0) != int(base.enable):
            return False
    except (TypeError, ValueError):
        return False
    if (live_s or "") != (base.server or ""):
        return False
    if base.pac_present:
        return live_a == (base.pac or "")
    return live_a is None


def _check_recordable(enable, server, pac, override=None):
    """Raise UnrecordableProxyValue for the first live value that a record
    can't hold as SNIper writes it back: a ProxyEnable that _flag can't read,
    or a ProxyServer / AutoConfigURL / ProxyOverride that isn't a string (a
    REG_DWORD, REG_BINARY bytes, a REG_MULTI_SZ list). A missing value is
    fine: _read_live and _read_override read it as 0, "" or None, all of which
    a record holds. ProxyOverride is checked only when given, as safe mode
    does: Compatibility mode never writes it."""
    if _flag(enable) is None:
        bad = ("ProxyEnable", enable)
    elif server is not None and not isinstance(server, str):
        bad = ("ProxyServer", server)
    elif pac is not None and not isinstance(pac, str):
        bad = ("AutoConfigURL", pac)
    elif override is not None and not isinstance(override, str):
        bad = ("ProxyOverride", override)
    else:
        return
    shown = repr(bad[1])
    if len(shown) > 40:
        shown = shown[:37] + "..."
    raise UnrecordableProxyValue(
        "the Windows proxy setting %s holds %s, which SNIper can't save and "
        "restore exactly, so it changed nothing. Re-save your proxy settings "
        "in Windows (Settings > Network & internet > Proxy), then start again."
        % (bad[0], shown))


# ── Durable restore baseline ───────────────────────────────────────────────────
def _read_baseline():
    """Return the Baseline of a *complete* durable record, or None when there
    is none. applied_server is None for a legacy record written before
    footprints were tracked; applied_mode is MODE_STATIC for it and for a
    v1.1.7 record. A baseline missing its commit marker (a crash mid-write) is
    treated as absent so a half-written record is never acted on.

    A genuine ProxyEnable that is missing, or that can't be read as a DWORD,
    reads as 0: Windows' own default, no manual proxy. Treating such a
    committed record as absent instead would be wrong, because Complete says
    the live values may already be SNIper's: the footprint would be stranded,
    and the next proxy_enable would capture it as the genuine baseline. The 0
    goes live only where a sound record would be restored too (over SNIper's
    own footprint, or for a legacy record), and turns the proxy off, so it
    fails open; the garbage itself is never written anywhere.

    For the same reasons a genuine ProxyServer, AutoConfigURL or
    ProxyOverride that isn't a string reads as "": no server, no script, no
    bypass list. SNIper only ever records them as REG_SZ, and a restore
    writes them back as REG_SZ, which takes nothing but a string.
    AutoConfigURL keeps its present flag, so the static footprint check still
    expects the PAC that SNIper emptied."""
    if not IS_WINDOWS:
        return None
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RESTORE_KEY)
    except OSError:
        return None
    try:
        try:
            if winreg.QueryValueEx(k, "Complete")[0] != 1:
                return None
        except OSError:
            return None
        try:
            enable = _flag(winreg.QueryValueEx(k, "ProxyEnable")[0]) or 0
        except OSError:
            enable = 0
        try:
            server = winreg.QueryValueEx(k, "ProxyServer")[0]
        except OSError:
            server = ""
        if not isinstance(server, str):
            server = ""
        try:
            present = winreg.QueryValueEx(k, "AutoConfigURLPresent")[0]
        except OSError:
            present = 0
        pac = None
        if present:
            try:
                pac = winreg.QueryValueEx(k, "AutoConfigURL")[0]
            except OSError:
                present = 0
            else:
                if not isinstance(pac, str):
                    pac = ""
        try:
            applied = winreg.QueryValueEx(k, "AppliedProxyServer")[0]
        except OSError:
            applied = None
        try:
            mode = winreg.QueryValueEx(k, "AppliedMode")[0]
        except OSError:
            mode = MODE_STATIC  # v1.1.7 and legacy records
        mode = MODE_PAC if mode == MODE_PAC else MODE_STATIC
        applied_pac_url = None
        if mode == MODE_PAC:
            try:
                applied_pac_url = winreg.QueryValueEx(k, "AppliedAutoConfigURL")[0]
            except OSError:
                pass  # can't match any live URL, so the restore backs off
        try:
            override_present = bool(
                winreg.QueryValueEx(k, "ProxyOverridePresent")[0])
        except OSError:
            override_present = None  # not recorded: no footprint ever wrote it
        override = None
        if override_present:
            try:
                override = winreg.QueryValueEx(k, "ProxyOverride")[0]
            except OSError:
                override_present = False
            else:
                if not isinstance(override, str):
                    override = ""
        applied_manual = (mode == MODE_PAC
                          and _query_int(k, "AppliedManualProxy") == 1)
        owner_pid = _query_int(k, "OwnerPid")
        owner_create_time = _query_int(k, "OwnerCreateTime")
        try:
            session_id = winreg.QueryValueEx(k, "SessionId")[0]
        except OSError:
            session_id = None  # an older record: no session can claim it
        if not isinstance(session_id, str):
            session_id = None
        return Baseline(enable, server or "", bool(present), pac, applied,
                        mode, applied_pac_url, owner_pid, owner_create_time,
                        session_id, override_present, override, applied_manual)
    finally:
        winreg.CloseKey(k)


def _query_int(k, name):
    """An integer value of the record, or None if it is missing or isn't
    one (ownership values are for matching only, never worth an error)."""
    try:
        return int(winreg.QueryValueEx(k, name)[0])
    except (OSError, TypeError, ValueError):
        return None


def _write_baseline(enable, server, pac, applied_server, applied_mode,
                    applied_pac_url, owner, session_id, override=None):
    """Persist the genuine baseline plus the footprint SNIper is applying and
    who applies it (owner is (pid, creation time)). The Complete marker is
    written LAST so an interruption mid-write leaves an incomplete record
    that _read_baseline ignores; pac is None when no PAC existed.

    AppliedAutoConfigURL, the genuine ProxyOverride (override, None when
    there was none) and the AppliedManualProxy marker are written in PAC mode
    only; a static record drops any left from a PAC record it replaces."""
    k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, _RESTORE_KEY)
    try:
        # Drop any stale marker first so a crash mid-rewrite is not acted on.
        try:
            winreg.DeleteValue(k, "Complete")
        except OSError:
            pass
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, int(enable))
        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, server or "")
        if pac is not None:
            winreg.SetValueEx(k, "AutoConfigURLPresent", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ, pac)
        else:
            winreg.SetValueEx(k, "AutoConfigURLPresent", 0, winreg.REG_DWORD, 0)
            try:
                winreg.DeleteValue(k, "AutoConfigURL")
            except OSError:
                pass
        winreg.SetValueEx(k, "AppliedProxyServer", 0, winreg.REG_SZ, applied_server)
        winreg.SetValueEx(k, "AppliedMode", 0, winreg.REG_SZ, applied_mode)
        if applied_mode == MODE_PAC:
            winreg.SetValueEx(k, "AppliedAutoConfigURL", 0, winreg.REG_SZ,
                              applied_pac_url)
            winreg.SetValueEx(k, "ProxyOverridePresent", 0, winreg.REG_DWORD,
                              int(override is not None))
            if override is not None:
                winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, override)
            else:
                try:
                    winreg.DeleteValue(k, "ProxyOverride")
                except OSError:
                    pass
            winreg.SetValueEx(k, "AppliedManualProxy", 0, winreg.REG_DWORD, 1)
        else:
            for name in ("AppliedAutoConfigURL", "ProxyOverridePresent",
                         "ProxyOverride", "AppliedManualProxy"):
                try:
                    winreg.DeleteValue(k, name)
                except OSError:
                    pass
        owner_pid, owner_create_time = owner
        winreg.SetValueEx(k, "OwnerPid", 0, winreg.REG_DWORD, int(owner_pid))
        winreg.SetValueEx(k, "OwnerCreateTime", 0, winreg.REG_QWORD,
                          int(owner_create_time))
        winreg.SetValueEx(k, "SessionId", 0, winreg.REG_SZ, session_id)
        winreg.SetValueEx(k, "Complete", 0, winreg.REG_DWORD, 1)  # commit LAST
    finally:
        winreg.CloseKey(k)


def _clear_baseline():
    """Remove the durable baseline so the next launch sees a clean state and
    performs no false recovery. Leaves no proxy-related residue; the namespace
    parent is removed too, but only when SNIper left it empty.

    The RunOnce safety net goes first. In the other order, an interruption
    in between would leave a blind restore behind with no record, and after
    a "kept" outcome it would overwrite the user's own change at sign-in;
    this way it can only leave a record, which recovery handles with its
    footprint check."""
    _clear_runonce()
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, _RESTORE_KEY)
    except OSError:
        pass
    try:
        p = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _SNIPER_KEY)
        try:
            n_sub, n_val, _ = winreg.QueryInfoKey(p)
        finally:
            winreg.CloseKey(p)
        if n_sub == 0 and n_val == 0:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, _SNIPER_KEY)
    except OSError:
        pass


# ── Compatibility-mode safety net (RunOnce) ───────────────────────────────────
def _debug(log_q, text):
    """Put a DEBUG line on log_q, if the caller gave one."""
    if log_q is not None:
        try:
            log_q.put(("DEBUG", text))
        except Exception:
            pass


def _reg_exe():
    """Windows' own reg.exe, by full path: the command must not depend on
    PATH, and SNIper's EXE may be gone by the time it runs."""
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return root.rstrip("\\") + r"\System32\reg.exe"


def _unwritable(text):
    """Why text can't be the quoted /d argument of a reg.exe command, or None.
    Windows hands a RunOnce command to reg.exe as-is, and reg.exe splits it
    into arguments by the usual rules: a quote inside the value ends it early,
    and a trailing backslash escapes the closing quote, which swallows /f so
    reg.exe waits forever for an overwrite confirmation."""
    if '"' in text:
        return "it contains a quote"
    if text.endswith("\\"):
        return "it ends with a backslash"
    return None


def _runonce_commands(enable, server, pac):
    """The RunOnce values that write the genuine values back to the live
    Internet Settings, as ([(value name, command)], [(name, why skipped)]).

    pac is the genuine AutoConfigURL that static mode emptied, or None when
    there was none to empty (an absent or empty one is never touched, so it
    needs no command). A value that a command can't carry exactly, or whose
    command would not fit in _RUNONCE_MAX_CHARS, is skipped rather than
    written wrong; the others are still written. _IE is the live key (the
    sandbox's own in tests), so a test can run the commands for real."""
    head = '"%s" add "HKCU\\%s" /v ' % (_reg_exe(), _IE)
    values = [("ProxyEnable", "REG_DWORD", "%d" % int(enable)),
              ("ProxyServer", "REG_SZ", server or "")]
    if pac:
        values.append(("AutoConfigURL", "REG_SZ", pac))
    commands, skipped = [], []
    for name, kind, data in values:
        if kind == "REG_SZ":
            reason = _unwritable(data)
            if reason:
                skipped.append((name, reason))
                continue
            data = '"%s"' % data
        command = "%s%s /t %s /d %s /f" % (head, name, kind, data)
        if len(command) > _RUNONCE_MAX_CHARS:
            skipped.append((name, "its command would be longer than %d characters"
                            % _RUNONCE_MAX_CHARS))
            continue
        commands.append((_RUNONCE_PREFIX + name, command))
    return commands, skipped


def _clear_runonce():
    """Delete every SNIperRestore* value from RunOnce. Never raises: a value
    that can't be deleted now goes at the next clear or launch."""
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUNONCE, 0,
                           winreg.KEY_READ | winreg.KEY_WRITE)
    except OSError:
        return  # no RunOnce key at all, so nothing of ours in it
    try:
        ours, i = [], 0
        while True:
            try:
                name = winreg.EnumValue(k, i)[0]
            except OSError:
                break  # no more values
            if name.lower().startswith(_RUNONCE_PREFIX.lower()):
                ours.append(name)
            i += 1
        for name in ours:
            try:
                winreg.DeleteValue(k, name)
            except OSError:
                pass
    finally:
        winreg.CloseKey(k)


def _write_runonce(enable, server, pac, log_q=None):
    """Replace the RunOnce safety net with commands that put these genuine
    values back (see _RUNONCE). Only ever runs after the record is committed
    and the static proxy is live, under the state lock.

    Best-effort and never raises: the net is a last resort, so failing to
    write it must not fail the apply. A write that fails half-way removes
    what it wrote, so the net is never a partial one by accident."""
    commands, skipped = _runonce_commands(enable, server, pac)
    for name, reason in skipped:
        _debug(log_q, "Sign-in safety net: %s left out, because %s."
               % (name, reason))
    _clear_runonce()  # a stale AutoConfigURL command must not survive
    try:
        k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, _RUNONCE)
        try:
            for name, command in commands:
                winreg.SetValueEx(k, name, 0, winreg.REG_SZ, command)
        finally:
            winreg.CloseKey(k)
    except OSError as e:
        _clear_runonce()
        _debug(log_q, "Sign-in safety net could not be written: %s" % (e,))


# ── Restore, per mode ──────────────────────────────────────────────────────────
def _restore_unlocked(base):
    """Undo the footprint one complete record describes and clear the record;
    see proxy_restore for the outcomes. The caller holds the state lock."""
    if base.applied_mode == MODE_PAC:
        return _restore_pac(base)
    return _restore_static(base)


def _restore_static(base):
    """Compatibility mode, and every v1.1.7 or legacy record: the genuine
    values go back only while the live proxy is exactly SNIper's footprint."""
    try:
        live = _read_live()
    except OSError:
        # Could not read the live state to compare; keep the baseline so a later
        # stop or the next launch can retry rather than risk a wrong write.
        return None

    # A legacy record (pre-footprint) cannot be checked, so fall back to the
    # prior contract and restore — safer than stranding the user.
    still_ours = base.applied_server is None or _is_footprint(
        live, base.applied_server, base.pac_present)
    if still_ours:
        try:
            _write_live_genuine(base.enable, base.server, base.pac_present, base.pac)
            _refresh()
        except OSError:
            # Write failed; keep the durable baseline so a retry can restore.
            return None
        _clear_baseline()
        return "restored"

    # The live proxy is no longer ours. Either it is already the genuine one
    # (someone restored it first) or the user took control. Leave it exactly
    # as found and just drop the record (no false recovery on the next launch).
    _clear_baseline()
    return "already" if _is_genuine(live, base) else "kept"


# What a safe-mode footprint did not write, in _pac_values.
_NOT_APPLIED = object()


def _pac_values(base, live, live_override):
    """The manual proxy values a safe-mode record accounts for, as (value
    name, live, genuine, applied) in the order a restore writes them back.
    applied is _NOT_APPLIED for a value the footprint left alone: before the
    manual proxy was added (applied_manual False) safe mode wrote only
    ProxyEnable=0. ProxyOverride is left out when the record doesn't hold its
    genuine value.

    ProxyEnable goes first, so a restore cut short never leaves the manual
    proxy enabled without the bypass list (see _apply_live_pac)."""
    live_e, live_s, _live_a = live
    if base.applied_manual:
        applied = (1, base.applied_server, _BYPASS_ALL)
    else:
        applied = (0, _NOT_APPLIED, _NOT_APPLIED)
    values = [("ProxyEnable", _flag(live_e), base.enable, applied[0]),
              ("ProxyServer", live_s, base.server or "", applied[1])]
    if base.override_present is not None:
        values.append(("ProxyOverride", live_override,
                       base.override if base.override_present else None,
                       applied[2]))
    return values


def _whose(live, genuine, applied):
    """Who a live value belongs to: "genuine" if it is the genuine one,
    "sniper" if it is the one SNIper applied, else "user", for someone who
    changed it after SNIper did. A value that is both is genuine: there is
    nothing to write back."""
    if live == genuine:
        return "genuine"
    if applied is not _NOT_APPLIED and live == applied:
        return "sniper"
    return "user"


def _restore_pac(base):
    """Safe mode. The script URL and the manual proxy are restored apart,
    each only while it is still SNIper's.

    Our script URL holds this session's random value, so while it is still
    there it is provably ours and always goes, replaced by the genuine PAC
    (or by nothing). The manual proxy goes back to its genuine values only if
    none of them was changed by someone else: a manual proxy the user set up
    meanwhile stays exactly as found. "kept" when anything the user changed
    was left in place, "restored" when SNIper wrote the genuine values back,
    "already" when nothing of SNIper's was left."""
    try:
        live = _read_live()
        live_override = (_read_override() if base.override_present is not None
                         else None)
    except OSError:
        return None  # keep the record for a retry, as in static mode

    manual = _pac_values(base, live, live_override)
    manual_whose = [_whose(lv, gv, av) for _, lv, gv, av in manual]
    script_whose = _whose(live[2], base.pac if base.pac_present else None,
                          base.applied_pac_url or _NOT_APPLIED)

    restore_manual = [(name, gv) for (name, _, gv, _), whose
                      in zip(manual, manual_whose) if whose == "sniper"]
    if "user" in manual_whose:
        restore_manual = []
    restore_script = script_whose == "sniper"
    if restore_manual or restore_script:
        try:
            _write_live_pac_genuine(
                restore_manual,
                (base.pac_present, base.pac) if restore_script else None)
            _refresh()
        except OSError:
            return None
    _clear_baseline()
    if "user" in manual_whose or script_whose == "user":
        return "kept"
    return "restored" if (restore_manual or restore_script) else "already"


def _put_back_override(base):
    """Before a record whose restore could not act is taken over for the
    other mode: if it is a safe-mode record and the live bypass list is still
    SNIper's "*", put the genuine list back. The static record that replaces
    it doesn't hold the list, and "*" would send every host past the static
    proxy. Nothing else is touched; OSError propagates."""
    if not base.applied_manual or base.override_present is None:
        return
    if _read_override() == _BYPASS_ALL:
        _write_live_pac_genuine(
            [("ProxyOverride", base.override if base.override_present else None)],
            None)


# ── Public API ─────────────────────────────────────────────────────────────────
def proxy_enable(addr, pac_url=None, session_id=None, log_q=None):
    """Point the per-user system proxy at SNIper.

    With pac_url None this is Compatibility mode: the static proxy addr. With
    a pac_url it is safe mode: AutoConfigURL=pac_url, plus the manual proxy
    addr with a bypass list of every host (ProxyEnable=1, ProxyServer=addr,
    ProxyOverride="*"); see the module doc.

    Records the genuine pre-SNIper configuration, plus the footprint being
    applied and its owner (the current process and session_id, a new one if
    None), to the durable baseline FIRST, then overwrites the live values, so
    an ungraceful termination is self-healable. Footprint-aware and idempotent:
    if a complete durable baseline for the same mode already exists it is the
    genuine one and is reused untouched (a re-apply must never capture SNIper's
    own footprint as the baseline); only the footprint and the owner are
    brought up to date, so the record always names the session that applied
    it last. A complete record from the OTHER mode is restored first, as
    launch recovery would, so its footprint is never stranded under a record
    that no longer describes it; if that restore cannot act, its genuine
    values are still the only genuine ones, so they are kept and the record is
    taken over for this mode. A safe-mode record taken over for Compatibility
    mode first gets its genuine bypass list put back, which the static
    footprint doesn't cover and whose "*" would send every host past it.

    Capture refuses a live value the record can't hold exactly (see
    _check_recordable): it raises UnrecordableProxyValue before anything is
    written, so the proxy is left as found and no record is created. On a
    mode switch the old record has been restored or released by then.

    In Compatibility mode the RunOnce safety net goes in last, after the
    record and the live values; safe mode removes any stale one instead.
    log_q, if given, gets a DEBUG line for each genuine value the net can't
    carry.

    Returns the genuine PAC URL (or None) so the caller can note that a PAC was
    temporarily disabled.
    """
    if not IS_WINDOWS:
        return None
    if _proxy_gpo_locked():
        # Per-user proxy is policy-locked: SNIper's writes have no effect, so
        # record no baseline (nothing would need restoring) and apply nothing.
        return None
    mode = MODE_STATIC if pac_url is None else MODE_PAC
    if session_id is None:
        session_id = secrets.token_hex(8)
    owner = procutil.process_identity()
    with _state_lock():
        try:
            existing = _read_baseline()
            if existing is not None and existing.applied_mode != mode:
                # Already under the lock: never re-enter proxy_restore().
                if _restore_unlocked(existing) is not None:
                    existing = None  # restored or released: a clean state now
                else:
                    _put_back_override(existing)
            if existing is None:
                # Clean state — the live values are the genuine baseline. (Startup
                # recovery has already restored-or-released and cleared any orphaned
                # footprint before we get here, so capturing the live state is
                # correct.)
                cur_e, cur_s, cur_a = _read_live()
                cur_o = _read_override() if mode == MODE_PAC else None
                _check_recordable(cur_e, cur_s, cur_a, cur_o)
                _write_baseline(cur_e, cur_s, cur_a, addr, mode, pac_url,
                                owner, session_id, override=cur_o)
                genuine_enable, genuine_server, genuine_pac = cur_e, cur_s, cur_a
            else:
                # A complete baseline already exists; it is the genuine config. Keep
                # it untouched and re-apply idempotently, but keep the remembered
                # footprint and owner in step with what we actually apply now.
                genuine_enable, genuine_server = existing.enable, existing.server
                genuine_pac = existing.pac if existing.pac_present else None
                genuine_o = existing.override if existing.override_present else None
                if mode == MODE_PAC and existing.override_present is None:
                    # The record doesn't hold the bypass list, so no footprint
                    # it describes ever wrote it: the live one is genuine.
                    genuine_o = _read_override()
                    _check_recordable(existing.enable, existing.server,
                                      genuine_pac, genuine_o)
                if (existing.applied_server != addr or existing.applied_mode != mode
                        or existing.applied_pac_url != pac_url
                        or (mode == MODE_PAC and not existing.applied_manual)
                        or (existing.owner_pid, existing.owner_create_time) != owner
                        or existing.session_id != session_id):
                    _write_baseline(existing.enable, existing.server, genuine_pac,
                                    addr, mode, pac_url, owner, session_id,
                                    override=genuine_o)
            if mode == MODE_PAC:
                _apply_live_pac(pac_url, addr)
            else:
                _apply_live(addr, clear_pac=bool(genuine_pac))
            # The sign-in safety net comes last: what it restores is already
            # durable, and what it undoes is already live.
            if mode == MODE_STATIC and RUNONCE_SAFETY_NET:
                _write_runonce(genuine_enable, genuine_server, genuine_pac, log_q)
            else:
                _clear_runonce()
            _refresh()
            return genuine_pac
        except OSError:
            # Best-effort. If the baseline write failed we never reached the live
            # overwrite, so the genuine state is intact (an incomplete baseline is
            # ignored on the next launch).
            return None


def proxy_restore(session_id=None, _launch=False):
    """Undo SNIper's own proxy change and clear the durable record. This is the
    single mechanism behind every restore: Stop, the session-end and accept-
    loop fail-safes, the on-launch self-heal and the guardian.

    The genuine baseline is written back ONLY when the live proxy is still
    exactly the footprint SNIper applied. If it has diverged (the user changed
    it during the session, or between a crash and this launch), the live proxy
    is left exactly as found — SNIper never overwrites a manual change with the
    stale baseline. Either way the durable record is dropped, and the RunOnce
    safety net with it.

    In safe mode the footprint is the script URL and the manual proxy, judged
    apart. While the URL is still there it is always replaced by the genuine
    PAC (or removed); the manual proxy goes back unless the user changed any
    of its values meanwhile, in which case it stays and the result is "kept".

    With a session_id (the guardian's), only that session's record is acted
    on: a record of another session, or an older one without a SessionId, is
    left completely untouched and the result is "not-ours".

    Returns "restored" when the genuine baseline was written back, "already"
    when the live proxy was no longer the footprint but already equal to the
    genuine values (someone restored first; nothing written), "kept" when a
    diverged (user-owned) live proxy was left in place, "not-ours" as above,
    or None when there was nothing to do (already clean, policy-locked, or the
    live state could not be read/written).

    _launch is for recover_orphaned_proxy only: with no complete record, a
    left-over RunOnce safety net is removed too, under the same hold.
    """
    if not IS_WINDOWS:
        return None
    with _state_lock():
        base = _read_baseline()
        if base is None:
            if _launch:
                _clear_runonce()
            return None
        if session_id is not None and base.session_id != session_id:
            return "not-ours"
        return _restore_unlocked(base)


def current_session_id():
    """The SessionId of the complete restore record, or None when there is
    no complete record (or it predates sessions). Read under the state lock,
    so a record half-way through a rewrite is never mistaken for another."""
    if not IS_WINDOWS:
        return None
    with _state_lock():
        base = _read_baseline()
    return None if base is None else base.session_id


def recover_orphaned_proxy():
    """On launch, before any new session, undo a proxy change stranded by a
    prior ungraceful exit and clear its durable baseline. Returns "restored",
    "already", "kept", or None (clean state — no false recovery) exactly as
    proxy_restore. No session is given: whoever wrote the record, it is
    stranded now, and this is the only process left to undo it.

    With no complete record, a RunOnce safety net still left over (an
    interruption between the two clears, or a record cleared by a SNIper
    that predates the net) is removed: nothing remains for it to restore.
    A record that can't be acted on now keeps its net, as it keeps itself.
    """
    if not IS_WINDOWS:
        return None
    return proxy_restore(_launch=True)
