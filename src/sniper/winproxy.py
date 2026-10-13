"""Windows system-proxy registry management.

SNIper points the per-user system proxy at itself in one of two modes:

- Safe mode ("pac", the default): ProxyEnable=0 and AutoConfigURL names a PAC
  script SNIper serves itself (see sniper.pac). ProxyServer is never touched.
  A dead SNIper is then harmless with no code having to run: the script can't
  be fetched, or the proxy it names refuses, and clients go DIRECT.
  ProxyEnable must be 0, because WinINet and Chromium fall back from a failed
  auto-config script to an enabled manual proxy, which would be the dead
  SNIper.
- Compatibility mode ("static"): ProxyEnable=1 and ProxyServer=127.0.0.1:port,
  for apps that ignore PAC scripts. This is exactly the v1.1.7 behavior.

The genuine pre-SNIper proxy configuration (the *restore baseline*) is written
to a durable per-user registry key BEFORE SNIper overwrites the live Internet
Settings values, and the commit marker is written last. This makes the restore
crash-durable: a graceful exit restores immediately, while an ungraceful one
(force kill, power loss, OS logoff/shutdown) leaves the baseline behind so the
next launch self-heals via recover_orphaned_proxy().

Both sides are footprint-aware. Capture (proxy_enable) never records SNIper's
own leftover state as the baseline. Restore (proxy_restore, and the launch
self-heal it backs) writes the genuine baseline back ONLY when the live proxy is
still exactly the footprint SNIper applied, all remembered durably: in static
mode the enable flag, the server address and the PAC-cleared state; in safe
mode the script URL, which holds a random value per session, so it is provably
SNIper's own. If the live proxy has diverged — the user changed it during the
session or between a crash and the next launch — SNIper treats the user as
having taken control: it leaves the live proxy untouched and simply drops the
durable record. SNIper only ever undoes its own change, never a manual one —
and never by guessing from the loopback address. The one exception is SNIper's
own one-off script URL, which is always removed while it is still there.

The record names the mode it was written for (AppliedMode). A record without
it was written by v1.1.7 and is static; one without AppliedProxyServer
predates footprints. Both are recovered exactly as before.

All operations stay HKCU-only (no admin), standard-library only, and guarded so
the module still imports on a non-Windows host where winreg is None.
"""
from __future__ import annotations

import ctypes
from collections import namedtuple

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

# The AppliedMode values. Anything else in a record (a missing value, or one
# from some future version) reads as static, whose exact footprint check then
# decides; at worst that leaves the live proxy alone.
MODE_STATIC = "static"
MODE_PAC    = "pac"

# A complete restore record, as _read_baseline returns it:
#   enable, server        the genuine ProxyEnable / ProxyServer
#   pac_present, pac      whether a genuine AutoConfigURL existed, and its value
#   applied_server        the address SNIper applied; None in a legacy record
#   applied_mode          MODE_PAC or MODE_STATIC
#   applied_pac_url       the script URL SNIper applied in PAC mode, else None
Baseline = namedtuple("Baseline", "enable server pac_present pac applied_server "
                                  "applied_mode applied_pac_url")

# WinINet options that make running clients pick up changed proxy settings.
_INTERNET_OPTION_REFRESH          = 37
_INTERNET_OPTION_SETTINGS_CHANGED = 39
_internet_set_option = None  # InternetSetOptionW, bound on first use


def _proxy_gpo_locked():
    """True if Group Policy disables per-user proxy settings.

    When HKLM ...\\Internet Settings\\ProxySettingsPerUser is 0, Windows
    ignores the per-user (HKCU) proxy values this program writes — the write
    succeeds but has no effect. Detecting it lets us warn the user instead of
    failing silently on a managed/corporate machine.
    """
    if not IS_WINDOWS:
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
    re-read them, so an apply or a restore takes effect at once."""
    if not IS_WINDOWS:
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


def _apply_live_pac(pac_url):
    """Point the live HKCU proxy at SNIper's PAC script (safe mode). Like
    _apply_live, only ever runs AFTER the durable baseline is committed.

    ProxyServer is never touched: with ProxyEnable=0 it is unused, so it
    keeps the user's value and a restore never has to write it. The URL goes
    in before the enable flag is cleared, so an interruption between the two
    leaves our URL next to the genuine flag: a state the restore recognizes
    and fully undoes. The other order could leave a genuine manual proxy
    switched off with no trace of SNIper left for the restore to find."""
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE, 0, winreg.KEY_WRITE)
    try:
        winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
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


def _write_live_pac_genuine(enable, pac_present, pac):
    """Undo safe mode on the live HKCU proxy: the genuine enable flag (unless
    enable is None, when the user's own flag stays as it is), then the genuine
    PAC, or no AutoConfigURL at all if there was none. ProxyServer is never
    written, because safe mode never changed it.

    The flag goes first, so an interruption leaves our URL in place for the
    next restore to find and finish (see _apply_live_pac). Only a missing
    AutoConfigURL is ignored; any other failure to remove our URL is an error
    that keeps the record for a retry."""
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE, 0, winreg.KEY_WRITE)
    try:
        if enable is not None:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, int(enable))
        if pac_present:
            winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ, pac or "")
        else:
            try:
                winreg.DeleteValue(k, "AutoConfigURL")
            except FileNotFoundError:
                pass
    finally:
        winreg.CloseKey(k)


def _is_footprint(live, applied_server, pac_present):
    """True if the live proxy is still EXACTLY what SNIper applied: enabled,
    pointed at the remembered server address, with the PAC in the state SNIper
    left it (emptied when there was a genuine PAC, absent otherwise). An exact
    match against what SNIper actually applied — never a guess from the loopback
    address — so a manual change of any of these fields reads as 'not mine'."""
    live_e, live_s, live_a = live
    if int(live_e or 0) != 1:
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


def _flag_set(value):
    """True unless a live ProxyEnable reads as 0. A value that can't be read
    as a number counts as set: it is not the 0 safe mode wrote, so it isn't
    SNIper's to change."""
    try:
        return int(value) != 0
    except (TypeError, ValueError):
        return True


# ── Durable restore baseline ───────────────────────────────────────────────────
def _read_baseline():
    """Return the Baseline of a *complete* durable record, or None when there
    is none. applied_server is None for a legacy record written before
    footprints were tracked; applied_mode is MODE_STATIC for it and for a
    v1.1.7 record. A baseline missing its commit marker (a crash mid-write) is
    treated as absent so a half-written record is never acted on."""
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
            enable = int(winreg.QueryValueEx(k, "ProxyEnable")[0])
        except OSError:
            enable = 0
        try:
            server = winreg.QueryValueEx(k, "ProxyServer")[0]
        except OSError:
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
        return Baseline(enable, server or "", bool(present), pac, applied,
                        mode, applied_pac_url)
    finally:
        winreg.CloseKey(k)


def _write_baseline(enable, server, pac, applied_server,
                    applied_mode=MODE_STATIC, applied_pac_url=None):
    """Persist the genuine baseline plus the footprint SNIper is applying. The
    Complete marker is written LAST so an interruption mid-write leaves an
    incomplete record that _read_baseline ignores; pac is None when no PAC
    existed. AppliedAutoConfigURL is written in PAC mode only."""
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
        else:
            try:
                winreg.DeleteValue(k, "AppliedAutoConfigURL")
            except OSError:
                pass
        winreg.SetValueEx(k, "Complete", 0, winreg.REG_DWORD, 1)  # commit LAST
    finally:
        winreg.CloseKey(k)


def _clear_baseline():
    """Remove the durable baseline so the next launch sees a clean state and
    performs no false recovery. Leaves no proxy-related residue; the namespace
    parent is removed too, but only when SNIper left it empty."""
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


# ── Restore, per mode ──────────────────────────────────────────────────────────
def _restore(base):
    """Undo the footprint one complete record describes and clear the record;
    see proxy_restore for the outcomes."""
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

    # The live proxy is no longer ours — the user took control. Leave it exactly
    # as found and just drop the record (no false recovery on the next launch).
    _clear_baseline()
    return "kept"


def _restore_pac(base):
    """Safe mode: decided by our one-off script URL, then the enable flag."""
    try:
        live_e, _live_s, live_a = _read_live()
    except OSError:
        return None  # keep the record for a retry, as in static mode

    if not base.applied_pac_url or live_a != base.applied_pac_url:
        # Our script was replaced or removed: the user or another tool owns the
        # configuration now. Write nothing, just drop the record.
        _clear_baseline()
        return "kept"

    # Our URL is still there. It holds this session's random value, so it is
    # provably ours and always goes, replaced by the genuine PAC (or by
    # nothing). The enable flag is ours only while it is still the 0 we set:
    # a manual proxy the user switched on meanwhile stays, flag and server.
    user_enabled = _flag_set(live_e)
    try:
        _write_live_pac_genuine(None if user_enabled else base.enable,
                                base.pac_present, base.pac)
        _refresh()
    except OSError:
        return None
    _clear_baseline()
    return "kept" if user_enabled else "restored"


# ── Public API ─────────────────────────────────────────────────────────────────
def proxy_enable(addr, pac_url=None):
    """Point the per-user system proxy at SNIper.

    With pac_url None this is Compatibility mode: the static proxy addr. With
    a pac_url it is safe mode: ProxyEnable=0 and AutoConfigURL=pac_url, with
    ProxyServer left alone (addr is still recorded, for diagnostics).

    Records the genuine pre-SNIper configuration, plus the footprint being
    applied, to the durable baseline FIRST, then overwrites the live values, so
    an ungraceful termination is self-healable. Footprint-aware and idempotent:
    if a complete durable baseline for the same mode already exists it is the
    genuine one and is reused untouched (a re-apply must never capture SNIper's
    own footprint as the baseline). A complete record from the OTHER mode is
    restored first, as launch recovery would, so its footprint is never
    stranded under a record that no longer describes it; if that restore
    cannot act, its genuine values are still the only genuine ones, so they
    are kept and the record is taken over for this mode.

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
    try:
        existing = _read_baseline()
        if existing is not None and existing.applied_mode != mode:
            if _restore(existing) is not None:
                existing = None  # restored or released: a clean state now
        if existing is None:
            # Clean state — the live values are the genuine baseline. (Startup
            # recovery has already restored-or-released and cleared any orphaned
            # footprint before we get here, so capturing the live state is
            # correct.)
            cur_e, cur_s, cur_a = _read_live()
            _write_baseline(cur_e, cur_s, cur_a, addr, mode, pac_url)
            genuine_pac = cur_a
        else:
            # A complete baseline already exists; it is the genuine config. Keep
            # it untouched and re-apply idempotently, but keep the remembered
            # footprint in step with what we actually apply now.
            genuine_pac = existing.pac if existing.pac_present else None
            if (existing.applied_server != addr or existing.applied_mode != mode
                    or existing.applied_pac_url != pac_url):
                _write_baseline(existing.enable, existing.server, genuine_pac,
                                addr, mode, pac_url)
        if mode == MODE_PAC:
            _apply_live_pac(pac_url)
        else:
            _apply_live(addr, clear_pac=bool(genuine_pac))
        _refresh()
        return genuine_pac
    except OSError:
        # Best-effort. If the baseline write failed we never reached the live
        # overwrite, so the genuine state is intact (an incomplete baseline is
        # ignored on the next launch).
        return None


def proxy_restore():
    """Undo SNIper's own proxy change and clear the durable record. This is the
    single mechanism behind both the graceful stop path and the on-launch
    self-heal.

    The genuine baseline is written back ONLY when the live proxy is still
    exactly the footprint SNIper applied. If it has diverged (the user changed
    it during the session, or between a crash and this launch), the live proxy
    is left exactly as found — SNIper never overwrites a manual change with the
    stale baseline. Either way the durable record is dropped.

    In safe mode the footprint is the script URL. While it is still there it is
    always replaced by the genuine PAC (or removed); if the user meanwhile
    switched on a manual proxy, that proxy stays and the result is "kept".

    Returns "restored" when the genuine baseline was written back, "kept" when a
    diverged (user-owned) live proxy was left in place, or None when there was
    nothing to do (already clean, policy-locked, or the live state could not be
    read/written).
    """
    if not IS_WINDOWS:
        return None
    base = _read_baseline()
    if base is None:
        return None
    return _restore(base)


def recover_orphaned_proxy():
    """On launch, before any new session, undo a proxy change stranded by a
    prior ungraceful exit and clear its durable baseline. Returns "restored",
    "kept", or None (clean state — no false recovery) exactly as proxy_restore.
    """
    if not IS_WINDOWS:
        return None
    return proxy_restore()
