"""Windows system-proxy registry management.

The genuine pre-SNIper proxy configuration (the *restore baseline*) is written
to a durable per-user registry key BEFORE SNIper overwrites the live Internet
Settings values, and the commit marker is written last. This makes the restore
crash-durable: a graceful exit restores immediately, while an ungraceful one
(force kill, power loss, OS logoff/shutdown) leaves the baseline behind so the
next launch self-heals via recover_orphaned_proxy().

Both sides are footprint-aware. Capture (proxy_enable) never records SNIper's
own leftover state as the baseline. Restore (proxy_restore, and the launch
self-heal it backs) writes the genuine baseline back ONLY when the live proxy is
still exactly the footprint SNIper applied (the enable flag, the server address,
and the PAC-cleared state it set, all remembered durably). If the live proxy has
diverged — the user changed it during the session or between a crash and the
next launch — SNIper treats the user as having taken control: it leaves the live
proxy untouched and simply drops the durable record. SNIper only ever undoes its
own change, never a manual one — and never by guessing from the loopback address.

All operations stay HKCU-only (no admin), standard-library only, and guarded so
the module still imports on a non-Windows host where winreg is None.
"""
from __future__ import annotations

import ctypes

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


def _refresh():
    if not IS_WINDOWS:
        return
    try:
        w = ctypes.windll.wininet
        w.InternetSetOptionW(0, 39, 0, 0); w.InternetSetOptionW(0, 37, 0, 0)
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


# ── Durable restore baseline ───────────────────────────────────────────────────
def _read_baseline():
    """Return (enable, server, pac_present, pac_value, applied_server) for a
    *complete* durable baseline, or None when there is none. applied_server is
    None for a legacy record written before footprints were tracked. A baseline
    missing its commit marker (a crash mid-write) is treated as absent so a
    half-written record is never acted on."""
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
        return enable, server or "", bool(present), pac, applied
    finally:
        winreg.CloseKey(k)


def _write_baseline(enable, server, pac, applied_server):
    """Persist the genuine baseline plus the footprint SNIper is applying. The
    Complete marker is written LAST so an interruption mid-write leaves an
    incomplete record that _read_baseline ignores; pac is None when no PAC
    existed."""
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


# ── Public API ─────────────────────────────────────────────────────────────────
def proxy_enable(addr):
    """Point the per-user system proxy at addr.

    Records the genuine pre-SNIper configuration, plus the footprint being
    applied, to the durable baseline FIRST, then overwrites the live values, so
    an ungraceful termination is self-healable. Footprint-aware and idempotent:
    if a complete durable baseline already exists it is the genuine one and is
    reused untouched (a re-apply must never capture SNIper's own footprint as
    the baseline).

    Returns the genuine PAC URL (or None) so the caller can note that a PAC was
    temporarily disabled.
    """
    if not IS_WINDOWS:
        return None
    if _proxy_gpo_locked():
        # Per-user proxy is policy-locked: SNIper's writes have no effect, so
        # record no baseline (nothing would need restoring) and apply nothing.
        return None
    try:
        existing = _read_baseline()
        if existing is None:
            # Clean state — the live values are the genuine baseline. (Startup
            # recovery has already restored-or-released and cleared any orphaned
            # footprint before we get here, so capturing the live state is
            # correct.)
            cur_e, cur_s, cur_a = _read_live()
            _write_baseline(cur_e, cur_s, cur_a, applied_server=addr)
            genuine_pac = cur_a
        else:
            # A complete baseline already exists; it is the genuine config. Keep
            # it untouched and re-apply idempotently, but keep the remembered
            # footprint in step with what we actually apply now.
            g_enable, g_server, g_present, g_pac, g_applied = existing
            genuine_pac = g_pac if g_present else None
            if g_applied != addr:
                _write_baseline(g_enable, g_server, genuine_pac, applied_server=addr)
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
    enable, server, pac_present, pac, applied_server = base
    try:
        live = _read_live()
    except OSError:
        # Could not read the live state to compare; keep the baseline so a later
        # stop or the next launch can retry rather than risk a wrong write.
        return None

    # A legacy record (pre-footprint) cannot be checked, so fall back to the
    # prior contract and restore — safer than stranding the user.
    still_ours = applied_server is None or _is_footprint(live, applied_server,
                                                         pac_present)
    if still_ours:
        try:
            _write_live_genuine(enable, server, pac_present, pac)
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


def recover_orphaned_proxy():
    """On launch, before any new session, undo a proxy change stranded by a
    prior ungraceful exit and clear its durable baseline. Returns "restored",
    "kept", or None (clean state — no false recovery) exactly as proxy_restore.
    """
    if not IS_WINDOWS:
        return None
    return proxy_restore()
