"""User settings behind the opt-in "Remember settings" option.

Single source of truth for the four GUI settings: Port, Fragment size,
Disable DoH and Verbose logging. Holds their defaults and valid ranges, the
sanitizing that keeps a bad value out, and loading, saving and clearing them
in the registry. ui.py takes its initial values and its Start validation
limits from here.

Storage is HKCU\\Software\\SNIper\\Settings, one REG_DWORD per setting, and
the key exists only while the user has opted in. Registry, never a file: the
EXE may run from a read-only USB stick or a folder the user cannot write to,
and the per-user registry needs no admin rights and keeps the settings when
the EXE is moved or replaced.

The parent key is shared with the safety-critical ProxyRestore record that
sniper.winproxy owns, so nothing here reads, writes or deletes anything under
ProxyRestore. Clearing deletes the Settings subkey alone, then the parent only
if that left it completely empty: the same rule winproxy._clear_baseline
follows.

No tkinter dependency, and every registry call is guarded so the module still
imports on a non-Windows host where winreg is None. There nothing is ever
stored: load_settings() reports nothing, and saving or clearing does nothing.
"""
from __future__ import annotations

from collections import namedtuple

from sniper.compat import IS_WINDOWS, winreg

# The settings key under HKEY_CURRENT_USER. The only place the path is
# spelled out (clear_settings derives the parent from it), so tests can
# redirect every read and write to a throwaway key by patching this name.
SETTINGS_KEY = r"Software\SNIper\Settings"

# Valid ranges, inclusive. ui.py checks Start against these same limits.
PORT_MIN, PORT_MAX = 1, 65535
FRAGMENT_MIN, FRAGMENT_MAX = 1, 512

_Field = namedtuple("_Field", "value_name default low high")

# Every setting, keyed by the name each settings dict uses here and in ui.py.
# value_name is the on-disk format: renaming one would silently drop what
# users have stored. The switches are stored as DWORD 0/1, hence 0..1.
_FIELDS = {
    "port":     _Field("Port",           8881,  PORT_MIN,     PORT_MAX),
    "fragment": _Field("FragmentSize",   2,     FRAGMENT_MIN, FRAGMENT_MAX),
    "no_doh":   _Field("DisableDoH",     False, 0,            1),
    "verbose":  _Field("VerboseLogging", False, 0,            1),
}


def default_settings():
    """Return a new dict with every setting at its default value."""
    return {name: field.default for name, field in _FIELDS.items()}


def sanitize(name, value):
    """Return value as a valid setting for name, or None if it is not one.

    Every setting is an int within its range; for the switches that is the
    0..1 they are stored as, and they come back as a bool. A bool passes for
    a switch but not for a number: Python counts True as the int 1, yet True
    is no port.
    """
    field = _FIELDS[name]
    is_switch = isinstance(field.default, bool)
    if not isinstance(value, int) or (isinstance(value, bool) and not is_switch):
        return None
    if not field.low <= value <= field.high:
        return None
    return bool(value) if is_switch else value


def load_settings():
    """Return the stored settings as a full dict, or None if none are stored.

    None means "use the defaults and leave Remember settings off": the user
    has not opted in, there is no registry, or the key cannot be opened. That
    last case is treated the same way so a registry problem can never stop
    startup. Each value is checked on its own: a missing, wrong-type or
    out-of-range one falls back to that setting's default, and unknown extra
    values are ignored.
    """
    if not IS_WINDOWS:
        return None
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, SETTINGS_KEY)
        try:
            values = default_settings()
            for name, field in _FIELDS.items():
                try:
                    data, kind = winreg.QueryValueEx(k, field.value_name)
                except OSError:
                    continue  # missing or unreadable: keep the default
                if kind != winreg.REG_DWORD:
                    continue  # wrong type, e.g. a string: keep the default
                value = sanitize(name, data)
                if value is not None:  # out of range: keep the default
                    values[name] = value
            return values
        finally:
            winreg.CloseKey(k)
    except OSError:
        return None


def save_settings(values):
    """Store every valid setting in values, a dict keyed like
    default_settings(). An invalid or missing entry is skipped, never
    written, so whatever was stored for it before stays.

    Returns False if a registry error stopped the write. Otherwise returns
    True, including on a host without a registry, where there is nothing
    to do.
    """
    if not IS_WINDOWS:
        return True
    try:
        k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, SETTINGS_KEY)
        try:
            for name, field in _FIELDS.items():
                value = sanitize(name, values.get(name))
                if value is not None:
                    winreg.SetValueEx(k, field.value_name, 0, winreg.REG_DWORD,
                                      int(value))
        finally:
            winreg.CloseKey(k)
    except OSError:
        return False
    return True


def clear_settings():
    """Forget the stored settings, so the next launch starts from the
    defaults with Remember settings off.

    Deletes the Settings subkey, then its parent only if that left the parent
    completely empty, so a sibling ProxyRestore record is never touched.
    Returns False if the stored settings could not be deleted. Otherwise
    returns True, including when none were stored or there is no registry.
    """
    if not IS_WINDOWS:
        return True
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, SETTINGS_KEY)
    except FileNotFoundError:
        pass  # nothing was stored: already forgotten
    except OSError:
        return False
    parent = SETTINGS_KEY.rpartition("\\")[0]
    try:
        p = winreg.OpenKey(winreg.HKEY_CURRENT_USER, parent)
        try:
            n_sub, n_val, _ = winreg.QueryInfoKey(p)
        finally:
            winreg.CloseKey(p)
        if n_sub == 0 and n_val == 0:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, parent)
    except OSError:
        pass  # best effort: an empty parent left behind is harmless
    return True
