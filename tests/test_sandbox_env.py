"""Tests for SNIPER_REGISTRY_SANDBOX, the variable that points a subprocess's
winproxy at a throwaway registry tree.

It is read once, at import, so every case runs in a fresh subprocess. Only
the exact shape the test fixture creates may redirect anything; every other
value must leave all keys at their real defaults, which is what keeps a stray
or hostile value from ever pointing SNIper somewhere else. Reading the module
values is all a case does: nothing here touches any registry.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid

import pytest

import sniper.winproxy as winproxy

_SRC = os.path.dirname(os.path.dirname(os.path.abspath(winproxy.__file__)))
HEX = uuid.uuid4().hex
VALID = "Software\\SNIper-pytest-" + HEX
DEFAULTS = {
    "ie": r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
    "sniper": r"Software\SNIper",
    "restore": r"Software\SNIper\ProxyRestore",
    "mutex": "SNIper_proxy_state",
    "sandboxed": False,
    "root": None,
}

# Print what the freshly imported winproxy resolved, and whether its WinINet
# refresh and its Group Policy check stay off the real machine.
_PROBE = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
import sniper.winproxy as w
calls = []
w._internet_set_option = lambda *a: calls.append(a) or 1
w.IS_WINDOWS = True
w._refresh()
state = {"ie": w._IE, "sniper": w._SNIPER_KEY, "restore": w._RESTORE_KEY,
         "mutex": w._STATE_MUTEX_NAME, "sandboxed": w._SANDBOXED,
         "root": w._SANDBOX_ROOT, "refreshed": bool(calls)}
if w._SANDBOXED:
    w.winreg = None  # the Group Policy check must not even look
    state["gpo_locked"] = w._proxy_gpo_locked()
print(json.dumps(state))
"""


def probe(value):
    env = dict(os.environ)
    env.pop("SNIPER_REGISTRY_SANDBOX", None)
    if value is not None:
        env["SNIPER_REGISTRY_SANDBOX"] = value
    proc = subprocess.run([sys.executable, "-c", _PROBE, _SRC], env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_a_valid_sandbox_redirects_everything():
    state = probe(VALID)
    assert state == {
        "ie": VALID + r"\Internet Settings",
        "sniper": VALID + r"\SNIper",
        "restore": VALID + r"\SNIper\ProxyRestore",
        "mutex": "SNIper_proxy_state_" + HEX,
        "sandboxed": True,
        "root": VALID,
        "refreshed": False,     # never tells real clients to reload
        "gpo_locked": False,    # and never consults the machine's policy
    }


def test_the_layout_matches_the_registry_sandbox_fixture(registry_sandbox):
    box = registry_sandbox
    state = probe(box.root)
    assert (state["ie"], state["sniper"], state["restore"], state["mutex"]) == \
        (box.ie, box.sniper_key, box.restore_key, box.mutex_name)
    assert box.env == {"SNIPER_REGISTRY_SANDBOX": box.root}


@pytest.mark.parametrize("value", [
    None,                                       # not set at all
    "",                                         # empty
    r"Software\SNIper",                         # the real key
    r"Software\SNIper-pytest-abc",              # a short id
    VALID[:-1],                                 # 31 hex digits
    VALID + "0",                                # 33 hex digits
    VALID + r"\..\x",                           # climbs out
    VALID + r"\SNIper",                         # a subkey
    VALID + "\\",                               # a trailing backslash
    "\\" + VALID,                               # a leading backslash
    r"HKCU\\" + VALID,                          # a root prefix
    r"HKEY_CURRENT_USER\\" + VALID,
    "Software\\SNIper-pytest-" + HEX.upper(),   # upper-case hex
    "software\\sniper-pytest-" + HEX,           # another spelling
    "Software/SNIper-pytest-" + HEX,            # a forward slash
    VALID + "\n",                               # a trailing newline
    " " + VALID,                                # surrounding blanks
    VALID + " ",
    "Software\\SNIper-pytest-" + "g" * 32,      # not hex
], ids=repr)
def test_anything_else_is_ignored_entirely(value):
    state = probe(value)
    refreshed = state.pop("refreshed")
    assert state == DEFAULTS
    assert refreshed is True  # the normal WinINet refresh, as for real


def test_the_validator_alone():
    # The same rule without a subprocess, plus what no environment variable
    # can carry (a NUL).
    assert winproxy._sandbox_root(VALID) == VALID
    for bad in (None, "", VALID + "\n", VALID + "\x00", "SOFTWARE\\SNIper-pytest-" + HEX):
        assert winproxy._sandbox_root(bad) is None
