"""In-memory stand-in for the winreg calls SNIper makes, shared by every test.

Unit tests patch FakeWinreg in for the real module (see the fake_reg fixture
in conftest.py), so they run headless on any OS and can never touch the real
registry. It mimics the parts of the real API the code relies on:

- registry names are case-insensitive: keys and value names are matched
  lower-cased, while each value's spelling is kept for record();
- a missing key or value raises FileNotFoundError, DeleteKey refuses a key that
  still has subkeys, and a REG_DWORD (REG_QWORD) write takes only an unsigned
  32-bit (64-bit) int;
- a handle can only do what it was opened for: OpenKey defaults to KEY_READ,
  CreateKey opens with full access, so writing through a read handle (or
  reading through a write-only one) fails the test instead of passing quietly
  as an access-denied error the code would swallow;
- HKEY_LOCAL_MACHINE can be read (Group Policy lives there) but never
  written: SNIper is HKCU-only, so any HKLM write fails the test.

calls records (function, key path) for every API call so a test can check what
was touched; HKLM paths are recorded with an "hklm\\" prefix. ops records
(function, key path, value name) for every value write or delete, in order. A
function named in fail, or a (function, key path) pair, raises
PermissionError as on an access-denied key. open counts handles not yet closed.
"""
from __future__ import annotations

# Same numbers as the real winreg constants.
HKEY_CURRENT_USER  = HKCU = 0x80000001
HKEY_LOCAL_MACHINE = HKLM = 0x80000002
REG_SZ, REG_BINARY, REG_DWORD, REG_QWORD = 1, 3, 4, 11
KEY_QUERY_VALUE = 0x0001
KEY_SET_VALUE   = 0x0002
KEY_NOTIFY      = 0x0010
KEY_READ        = 0x20019
KEY_WRITE       = 0x20006
KEY_ALL_ACCESS  = 0xF003F

# "No such value". Equal to None on purpose: winproxy._read_live reports a
# missing AutoConfigURL as None, so live() tuples compare directly with what
# the code under test returns, and absent stays distinct from "" (empty).
ABSENT = None

IE_KEY      = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
IE_POLICY   = r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
SNIPER_KEY  = r"Software\SNIper"
RESTORE_KEY = r"Software\SNIper\ProxyRestore"
SETTINGS_KEY = r"Software\SNIper\Settings"

_HKLM_PREFIX = "hklm\\"
_NO_WRITE = "SNIper must never write outside HKCU"


class _Handle:
    def __init__(self, root, path, access):
        self.root = root
        self.path = path        # lower-cased; HKLM paths carry _HKLM_PREFIX
        self.access = access
        self.closed = False


class FakeWinreg:
    def __init__(self):
        # The constants the code under test reads off winreg.
        self.HKEY_CURRENT_USER = HKEY_CURRENT_USER
        self.HKEY_LOCAL_MACHINE = HKEY_LOCAL_MACHINE
        self.REG_SZ, self.REG_BINARY = REG_SZ, REG_BINARY
        self.REG_DWORD, self.REG_QWORD = REG_DWORD, REG_QWORD
        self.KEY_READ, self.KEY_WRITE, self.KEY_NOTIFY = KEY_READ, KEY_WRITE, KEY_NOTIFY
        # HKCU: {lower-cased key path: {lower-cased value name: (data, kind)}}
        self.keys = {}
        # HKLM, kept apart so it can be read but never written.
        self.hklm = {}
        self._names = {}        # (store id, key path, lower name) -> spelling
        self.calls = []
        self.ops = []
        self.fail = set()
        self.open = 0

    # ── Helpers for the tests themselves (not recorded in calls) ────────────
    def put(self, path, name=None, data=None, kind=REG_DWORD):
        """Create path and its parents in HKCU; also store a value if name is
        given."""
        self._put(self.keys, path, name, data, kind)

    def exists(self, path):
        return path.lower() in self.keys

    def value(self, path, name):
        return self.keys[path.lower()].get(name.lower())

    def set_gpo_locked(self, locked):
        """Write the Group Policy switch SNIper checks: ProxySettingsPerUser
        is 0 when per-user proxy settings are locked, 1 when they are not."""
        self._put(self.hklm, IE_POLICY, "ProxySettingsPerUser",
                  0 if locked else 1, REG_DWORD)

    def set_live(self, enable=0, server="", pac=ABSENT):
        """Set the live Internet Settings values; ABSENT removes one."""
        self.put(IE_KEY)
        for name, data, kind in (("ProxyEnable", enable, REG_DWORD),
                                 ("ProxyServer", server, REG_SZ),
                                 ("AutoConfigURL", pac, REG_SZ)):
            if data is ABSENT:
                self.keys[IE_KEY.lower()].pop(name.lower(), None)
            else:
                self.put(IE_KEY, name, data, kind)

    def live(self):
        """(ProxyEnable, ProxyServer, AutoConfigURL) as stored, ABSENT for a
        missing value."""
        vals = self.keys.get(IE_KEY.lower(), {})

        def get(name):
            entry = vals.get(name.lower())
            return ABSENT if entry is None else entry[0]
        return get("ProxyEnable"), get("ProxyServer"), get("AutoConfigURL")

    def record(self, types=False):
        """The ProxyRestore values as {name: data} ({name: (data, kind)} with
        types=True), or None when there is no record."""
        path = RESTORE_KEY.lower()
        if path not in self.keys:
            return None
        return {self._names.get((id(self.keys), path, lname), lname):
                (entry if types else entry[0])
                for lname, entry in self.keys[path].items()}

    def ie_writes(self):
        """Every value write/delete on the live Internet Settings key."""
        return [op for op in self.ops if op[1] == IE_KEY.lower()]

    # ── Internals ───────────────────────────────────────────────────────────
    def _put(self, store, path, name, data, kind):
        parts = path.lower().split("\\")
        for i in range(1, len(parts) + 1):
            store.setdefault("\\".join(parts[:i]), {})
        if name is not None:
            store[path.lower()][name.lower()] = (data, kind)
            self._names[(id(store), path.lower(), name.lower())] = name

    def _call(self, func, path):
        self.calls.append((func, path))
        if func in self.fail or (func, path) in self.fail:
            raise PermissionError(13, "Access is denied")

    def _root(self, root, write):
        if root == HKEY_LOCAL_MACHINE:
            assert not write, _NO_WRITE
            return self.hklm, _HKLM_PREFIX
        assert root == HKEY_CURRENT_USER, "unexpected registry root %r" % (root,)
        return self.keys, ""

    def _store(self, hkey):
        return self.hklm if hkey.root == HKEY_LOCAL_MACHINE else self.keys

    def _local(self, hkey):
        return hkey.path[len(_HKLM_PREFIX):] if hkey.root == HKEY_LOCAL_MACHINE else hkey.path

    def _check_open(self, hkey, need, what):
        assert not hkey.closed, "use of a closed key"
        assert hkey.access & need == need, (
            "%s through a handle opened without the access it needs" % what)

    def _children(self, store, path):
        prefix = path + "\\"
        return [k for k in store
                if k.startswith(prefix) and "\\" not in k[len(prefix):]]

    def _missing(self):
        return FileNotFoundError(2, "The system cannot find the file specified")

    def _handle(self, root, path, access):
        self.open += 1
        return _Handle(root, path, access)

    # ── The winreg API ──────────────────────────────────────────────────────
    def OpenKey(self, root, sub_key, reserved=0, access=KEY_READ):
        store, prefix = self._root(root, write=False)
        path = sub_key.lower()
        self._call("OpenKey", prefix + path)
        if path not in store:
            raise self._missing()
        return self._handle(root, prefix + path, access)

    def CreateKey(self, root, sub_key):
        store, prefix = self._root(root, write=True)
        path = sub_key.lower()
        self._call("CreateKey", prefix + path)
        self._put(store, path, None, None, None)
        return self._handle(root, prefix + path, KEY_ALL_ACCESS)

    def CloseKey(self, hkey):
        assert not hkey.closed, "key closed twice"
        hkey.closed = True
        self.open -= 1

    def QueryValueEx(self, hkey, name):
        self._check_open(hkey, KEY_QUERY_VALUE, "QueryValueEx")
        self._call("QueryValueEx", hkey.path)
        try:
            return self._store(hkey)[self._local(hkey)][name.lower()]
        except KeyError:
            raise self._missing()

    def SetValueEx(self, hkey, name, reserved, kind, data):
        assert hkey.root == HKEY_CURRENT_USER, _NO_WRITE
        self._check_open(hkey, KEY_SET_VALUE, "SetValueEx")
        self._call("SetValueEx", hkey.path)
        if kind == REG_DWORD:
            assert type(data) is int and 0 <= data <= 0xFFFFFFFF, data
        elif kind == REG_QWORD:
            assert type(data) is int and 0 <= data <= 0xFFFFFFFFFFFFFFFF, data
        self.ops.append(("SetValueEx", hkey.path, name))
        self.keys[hkey.path][name.lower()] = (data, kind)
        self._names[(id(self.keys), hkey.path, name.lower())] = name

    def DeleteValue(self, hkey, name):
        assert hkey.root == HKEY_CURRENT_USER, _NO_WRITE
        self._check_open(hkey, KEY_SET_VALUE, "DeleteValue")
        self._call("DeleteValue", hkey.path)
        values = self.keys[hkey.path]
        if name.lower() not in values:
            raise self._missing()
        self.ops.append(("DeleteValue", hkey.path, name))
        del values[name.lower()]

    def QueryInfoKey(self, hkey):
        self._check_open(hkey, KEY_QUERY_VALUE, "QueryInfoKey")
        self._call("QueryInfoKey", hkey.path)
        store, path = self._store(hkey), self._local(hkey)
        return len(self._children(store, path)), len(store[path]), 0

    def DeleteKey(self, root, sub_key):
        store, prefix = self._root(root, write=True)
        path = sub_key.lower()
        self._call("DeleteKey", prefix + path)
        if path not in store:
            raise self._missing()
        if self._children(store, path):
            raise PermissionError(13, "Access is denied")
        self.ops.append(("DeleteKey", path, None))
        del store[path]
