"""Unit tests for sniper.settings, the store behind "Remember settings".

Everything runs headless on any OS, without tkinter and against FakeWinreg,
a small in-memory stand-in for the winreg calls the module makes, patched in
with monkeypatch. The one exception is the Windows-only round trip at the
end, which uses a throwaway key (never the real HKCU\\Software\\SNIper) and
always removes it.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import uuid

import pytest

import sniper.settings as settings
import sniper.winproxy as winproxy
from sniper.compat import IS_WINDOWS

SETTINGS = r"Software\SNIper\Settings"
PARENT   = r"Software\SNIper"
RESTORE  = r"Software\SNIper\ProxyRestore"

# Same numbers as the real winreg constants.
HKCU = 0x80000001
REG_SZ, REG_BINARY, REG_DWORD, REG_QWORD = 1, 3, 4, 11

STORED = {"port": 9123, "fragment": 7, "no_doh": True, "verbose": True}


class _Handle:
    def __init__(self, path):
        self.path = path
        self.closed = False


class FakeWinreg:
    """In-memory stand-in for the winreg calls sniper.settings makes.

    keys maps each lower-cased key path (registry names are case-insensitive)
    to {lower-cased value name: (data, type)}. As with the real API, a missing
    key or value raises FileNotFoundError, DeleteKey refuses a key that still
    has subkeys, and a REG_DWORD write takes only an unsigned 32-bit int. Only
    HKEY_CURRENT_USER exists, so reaching outside it fails the test.

    calls records (function, key path) for every API call so a test can check
    what was touched; a function named in fail raises PermissionError, as on
    an access-denied key; open counts handles not yet closed.
    """

    def __init__(self):
        # The constants sniper.settings reads off winreg.
        self.HKEY_CURRENT_USER = HKCU
        self.REG_DWORD = REG_DWORD
        self.keys = {}
        self.calls = []
        self.fail = set()
        self.open = 0

    # ── Helpers for the tests themselves (not recorded in calls) ────────────
    def put(self, path, name=None, data=None, kind=REG_DWORD):
        """Create path and its parents; also store a value if name is given."""
        parts = path.lower().split("\\")
        for i in range(1, len(parts) + 1):
            self.keys.setdefault("\\".join(parts[:i]), {})
        if name is not None:
            self.keys[path.lower()][name.lower()] = (data, kind)

    def exists(self, path):
        return path.lower() in self.keys

    def value(self, path, name):
        return self.keys[path.lower()].get(name.lower())

    # ── Internals ───────────────────────────────────────────────────────────
    def _call(self, func, path):
        self.calls.append((func, path))
        if func in self.fail:
            raise PermissionError(13, "Access is denied")

    def _key(self, func, root, sub_key):
        assert root == self.HKEY_CURRENT_USER, "settings must stay in HKCU"
        path = sub_key.lower()
        self._call(func, path)
        return path

    def _children(self, path):
        prefix = path + "\\"
        return [k for k in self.keys
                if k.startswith(prefix) and "\\" not in k[len(prefix):]]

    def _missing(self):
        return FileNotFoundError(2, "The system cannot find the file specified")

    def _handle(self, path):
        self.open += 1
        return _Handle(path)

    # ── The winreg API ──────────────────────────────────────────────────────
    def OpenKey(self, root, sub_key, reserved=0, access=0x20019):
        path = self._key("OpenKey", root, sub_key)
        if path not in self.keys:
            raise self._missing()
        return self._handle(path)

    def CreateKey(self, root, sub_key):
        path = self._key("CreateKey", root, sub_key)
        self.put(path)
        return self._handle(path)

    def CloseKey(self, hkey):
        assert not hkey.closed, "key closed twice"
        hkey.closed = True
        self.open -= 1

    def QueryValueEx(self, hkey, name):
        self._call("QueryValueEx", hkey.path)
        try:
            return self.keys[hkey.path][name.lower()]
        except KeyError:
            raise self._missing()

    def SetValueEx(self, hkey, name, reserved, kind, data):
        self._call("SetValueEx", hkey.path)
        if kind == REG_DWORD:
            assert type(data) is int and 0 <= data <= 0xFFFFFFFF, data
        self.keys[hkey.path][name.lower()] = (data, kind)

    def QueryInfoKey(self, hkey):
        self._call("QueryInfoKey", hkey.path)
        return len(self._children(hkey.path)), len(self.keys[hkey.path]), 0

    def DeleteKey(self, root, sub_key):
        path = self._key("DeleteKey", root, sub_key)
        if path not in self.keys:
            raise self._missing()
        if self._children(path):
            raise PermissionError(13, "Access is denied")
        del self.keys[path]


@pytest.fixture
def reg(monkeypatch):
    """A fresh FakeWinreg in place of the registry, as if on Windows."""
    fake = FakeWinreg()
    monkeypatch.setattr(settings, "winreg", fake)
    monkeypatch.setattr(settings, "IS_WINDOWS", True)
    yield fake
    assert fake.open == 0, "a registry key was left open"


# ── Defaults, limits and sanitizing ──────────────────────────────────────────
def test_defaults():
    assert settings.default_settings() == {
        "port": 8881, "fragment": 2, "no_doh": False, "verbose": False}
    assert (settings.PORT_MIN, settings.PORT_MAX) == (1, 65535)
    assert (settings.FRAGMENT_MIN, settings.FRAGMENT_MAX) == (1, 512)
    for name, value in settings.default_settings().items():
        assert settings.sanitize(name, value) == value
    # Each call hands out a fresh dict, so a caller can't corrupt the defaults.
    settings.default_settings()["port"] = 1
    assert settings.default_settings()["port"] == 8881


def test_storage_location():
    # The Settings key is a sibling of winproxy's restore record under the
    # same parent, which is what clear_settings' parent rule assumes.
    assert settings.SETTINGS_KEY == SETTINGS
    assert settings.SETTINGS_KEY.rpartition("\\")[0] == winproxy._SNIPER_KEY
    assert winproxy._RESTORE_KEY == RESTORE


@pytest.mark.parametrize("name, value, expected", [
    # Boundaries.
    ("port", 1, 1), ("port", 65535, 65535),
    ("port", 0, None), ("port", 65536, None), ("port", -1, None),
    ("port", 0xFFFFFFFF, None),
    ("fragment", 1, 1), ("fragment", 512, 512),
    ("fragment", 0, None), ("fragment", 513, None),
    # Missing or wrong type: True is an int to Python, but no port.
    ("port", None, None), ("port", "8881", None), ("port", 8881.0, None),
    ("port", True, None), ("fragment", False, None),
    # Switches take a bool or the DWORD 0/1 they are stored as.
    ("no_doh", True, True), ("no_doh", False, False),
    ("no_doh", 1, True), ("no_doh", 0, False),
    ("verbose", 2, None), ("verbose", -1, None), ("verbose", "1", None),
    ("verbose", 1.0, None), ("verbose", None, None),
])
def test_sanitize(name, value, expected):
    got = settings.sanitize(name, value)
    assert got == expected
    assert type(got) is type(expected)  # a switch comes back as a real bool


# ── Loading ──────────────────────────────────────────────────────────────────
def test_nothing_stored(reg):
    assert settings.load_settings() is None
    assert reg.keys == {}  # loading never creates anything


def test_empty_key_counts_as_remembered(reg):
    # The key itself is the opt-in marker; absent values are just defaults.
    reg.put(SETTINGS)
    assert settings.load_settings() == settings.default_settings()


def test_load_stored_values(reg):
    reg.put(SETTINGS, "Port", 9123)
    reg.put(SETTINGS, "FragmentSize", 7)
    reg.put(SETTINGS, "DisableDoH", 1)
    reg.put(SETTINGS, "VerboseLogging", 1)
    assert settings.load_settings() == STORED


def test_load_checks_each_value_on_its_own(reg):
    reg.put(SETTINGS, "Port", "9123", REG_SZ)  # wrong type
    reg.put(SETTINGS, "FragmentSize", 513)     # out of range
    reg.put(SETTINGS, "DisableDoH", 1)         # valid
    # VerboseLogging is missing.
    reg.put(SETTINGS, "Theme", 3)              # unknown: ignored
    assert settings.load_settings() == {
        "port": 8881, "fragment": 2, "no_doh": True, "verbose": False}


@pytest.mark.parametrize("value_name, data, kind, name, expected", [
    ("Port", 1, REG_DWORD, "port", 1),
    ("Port", 65535, REG_DWORD, "port", 65535),
    ("Port", 0, REG_DWORD, "port", 8881),
    ("Port", 65536, REG_DWORD, "port", 8881),
    ("Port", 0xFFFFFFFF, REG_DWORD, "port", 8881),
    ("Port", 9123, REG_QWORD, "port", 8881),
    ("FragmentSize", 1, REG_DWORD, "fragment", 1),
    ("FragmentSize", 512, REG_DWORD, "fragment", 512),
    ("FragmentSize", 0, REG_DWORD, "fragment", 2),
    ("FragmentSize", b"\x07\x00\x00\x00", REG_BINARY, "fragment", 2),
    ("DisableDoH", 0, REG_DWORD, "no_doh", False),
    ("DisableDoH", 2, REG_DWORD, "no_doh", False),
    ("VerboseLogging", 1, REG_DWORD, "verbose", True),
    ("VerboseLogging", "1", REG_SZ, "verbose", False),
])
def test_load_one_value(reg, value_name, data, kind, name, expected):
    reg.put(SETTINGS, value_name, data, kind)
    want = settings.default_settings()
    want[name] = expected
    assert settings.load_settings() == want


# ── Saving ───────────────────────────────────────────────────────────────────
def test_round_trip(reg):
    assert settings.save_settings(STORED) is True
    assert settings.load_settings() == STORED
    # One DWORD per setting, the switches as 0/1.
    assert reg.value(SETTINGS, "Port") == (9123, REG_DWORD)
    assert reg.value(SETTINGS, "FragmentSize") == (7, REG_DWORD)
    assert reg.value(SETTINGS, "DisableDoH") == (1, REG_DWORD)
    assert reg.value(SETTINGS, "VerboseLogging") == (1, REG_DWORD)

    defaults = settings.default_settings()
    assert settings.save_settings(defaults) is True
    assert settings.load_settings() == defaults
    assert reg.value(SETTINGS, "DisableDoH") == (0, REG_DWORD)


def test_save_keeps_stored_value_of_an_invalid_field(reg):
    settings.save_settings(STORED)
    # Port holds text (the UI passes None) and Fragment is out of range: both
    # keep what was stored, while the valid switches are still saved.
    on_screen = {"port": None, "fragment": 999, "no_doh": False, "verbose": False}
    assert settings.save_settings(on_screen) is True
    assert settings.load_settings() == {
        "port": 9123, "fragment": 7, "no_doh": False, "verbose": False}


def test_save_never_writes_an_invalid_value(reg):
    on_screen = {"port": "abc", "fragment": 0, "no_doh": True}  # verbose missing
    assert settings.save_settings(on_screen) is True
    assert reg.value(SETTINGS, "Port") is None
    assert reg.value(SETTINGS, "FragmentSize") is None
    assert reg.value(SETTINGS, "VerboseLogging") is None
    assert settings.load_settings() == {
        "port": 8881, "fragment": 2, "no_doh": True, "verbose": False}


# ── Clearing ─────────────────────────────────────────────────────────────────
def test_clear_removes_settings_and_empty_parent(reg):
    settings.save_settings(STORED)
    assert settings.clear_settings() is True
    assert not reg.exists(SETTINGS)
    assert not reg.exists(PARENT)
    assert settings.load_settings() is None


def test_clear_leaves_proxy_restore_alone(reg):
    # A restore record as winproxy writes it while the proxy is running.
    reg.put(RESTORE, "ProxyEnable", 0)
    reg.put(RESTORE, "ProxyServer", "", REG_SZ)
    reg.put(RESTORE, "AppliedProxyServer", "127.0.0.1:8881", REG_SZ)
    reg.put(RESTORE, "Complete", 1)
    record = dict(reg.keys[RESTORE.lower()])

    settings.save_settings(STORED)
    settings.load_settings()
    assert settings.clear_settings() is True

    assert not reg.exists(SETTINGS)
    assert reg.exists(PARENT)  # still holds ProxyRestore, so kept
    assert reg.keys[RESTORE.lower()] == record
    assert [c for c in reg.calls if c[1].startswith(RESTORE.lower())] == []


def test_clear_keeps_parent_that_holds_values(reg):
    reg.put(PARENT, "Unrelated", 1)
    settings.save_settings(STORED)
    assert settings.clear_settings() is True
    assert not reg.exists(SETTINGS)
    assert reg.value(PARENT, "Unrelated") == (1, REG_DWORD)


def test_clear_with_nothing_stored(reg):
    assert settings.clear_settings() is True
    assert reg.keys == {}


# ── Registry errors never raise ──────────────────────────────────────────────
def test_load_error_opening_key(reg):
    settings.save_settings(STORED)
    reg.fail.add("OpenKey")
    assert settings.load_settings() is None


def test_load_error_reading_values(reg):
    settings.save_settings(STORED)
    reg.fail.add("QueryValueEx")
    assert settings.load_settings() == settings.default_settings()


@pytest.mark.parametrize("failing", ["CreateKey", "SetValueEx"])
def test_save_error(reg, failing):
    reg.fail.add(failing)
    assert settings.save_settings(STORED) is False


def test_clear_error_deleting_settings(reg):
    settings.save_settings(STORED)
    reg.fail.add("DeleteKey")
    assert settings.clear_settings() is False
    assert settings.load_settings() == STORED


@pytest.mark.parametrize("failing", ["OpenKey", "QueryInfoKey"])
def test_clear_error_checking_parent(reg, failing):
    settings.save_settings(STORED)
    reg.fail.add(failing)
    # The settings are gone; tidying the parent away is only best effort.
    assert settings.clear_settings() is True
    assert not reg.exists(SETTINGS)
    assert reg.exists(PARENT)


# ── No registry (non-Windows) ────────────────────────────────────────────────
def test_without_a_registry_nothing_is_stored(monkeypatch):
    monkeypatch.setattr(settings, "winreg", None)
    monkeypatch.setattr(settings, "IS_WINDOWS", False)
    assert settings.load_settings() is None
    assert settings.save_settings(STORED) is True
    assert settings.clear_settings() is True
    assert settings.load_settings() is None


def test_imports_without_tkinter_or_winreg():
    # A fresh interpreter in which neither module can be imported, as on a
    # headless non-Windows host. A None entry in sys.modules makes any
    # "import tkinter" or "import winreg" raise ImportError.
    code = textwrap.dedent("""
        import sys
        sys.modules["tkinter"] = None
        sys.modules["winreg"] = None
        sys.path.insert(0, sys.argv[1])
        import sniper.settings as s
        assert s.winreg is None and not s.IS_WINDOWS
        assert s.load_settings() is None
        assert s.save_settings(s.default_settings()) is True
        assert s.clear_settings() is True
    """)
    src = os.path.dirname(os.path.dirname(os.path.abspath(settings.__file__)))
    proc = subprocess.run([sys.executable, "-c", code, src],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


# ── Real registry (Windows only) ─────────────────────────────────────────────
@pytest.mark.skipif(not IS_WINDOWS, reason="needs the Windows registry")
def test_real_registry_round_trip(monkeypatch):
    import winreg

    # A throwaway sibling of Software\SNIper, so the real key is never used.
    parent = r"Software\SNIper-pytest-" + uuid.uuid4().hex
    key = parent + r"\Settings"
    monkeypatch.setattr(settings, "SETTINGS_KEY", key)
    try:
        assert settings.load_settings() is None
        wanted = {"port": 9123, "fragment": 7, "no_doh": True, "verbose": False}
        assert settings.save_settings(wanted) is True
        assert settings.load_settings() == wanted

        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key)
        try:
            assert winreg.QueryValueEx(k, "Port") == (9123, winreg.REG_DWORD)
            assert winreg.QueryValueEx(k, "DisableDoH") == (1, winreg.REG_DWORD)
        finally:
            winreg.CloseKey(k)

        assert settings.clear_settings() is True
        assert settings.load_settings() is None
        with pytest.raises(FileNotFoundError):  # the emptied parent went too
            winreg.CloseKey(winreg.OpenKey(winreg.HKEY_CURRENT_USER, parent))
    finally:
        for path in (key, parent):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
            except OSError:
                pass
