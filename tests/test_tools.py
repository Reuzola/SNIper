"""Tests for tools/proxy_state.py, the read-only proxy diagnostic.

The subprocess runs read the developer's real settings; together with the
session's real-proxy guard they also show the tool changes nothing. The
verdict and rendering are tested on synthetic states.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import os
import subprocess
import sys

import pytest

from sniper.compat import IS_WINDOWS

_TOOL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "..", "tools", "proxy_state.py"))
KEYS = {"live", "winhttp_ie_config", "record", "runonce", "processes", "verdict"}


@pytest.fixture(scope="module")
def tool():
    spec = importlib.util.spec_from_file_location("proxy_state", _TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(*args):
    return subprocess.run([sys.executable, _TOOL] + list(args),
                          capture_output=True, text=True, timeout=60)


# ── As a program ─────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_json_output():
    proc = _run("--json")
    assert proc.returncode == 0, proc.stderr
    if not IS_WINDOWS:
        assert proc.stdout.strip() == "Windows only"
        return
    state = json.loads(proc.stdout)
    assert set(state) == KEYS
    assert set(state["live"]) == {"ProxyEnable", "ProxyServer", "ProxyOverride",
                                  "AutoConfigURL"}
    assert state["verdict"] in {"CLEAN", "SNIPER ACTIVE", "STRANDED", "UNKNOWN"}
    assert "error" in state["winhttp_ie_config"] or \
        {"auto_detect", "auto_config_url", "proxy", "proxy_bypass"} <= set(state["winhttp_ie_config"])
    assert state["processes"] is None or isinstance(state["processes"], list)
    # The tool never lists itself.
    assert not any(_TOOL.lower() in (p["command_line"] or "").lower()
                   for p in state["processes"] or [])


@pytest.mark.slow
def test_text_output():
    proc = _run()
    assert proc.returncode == 0, proc.stderr
    if not IS_WINDOWS:
        assert proc.stdout.strip() == "Windows only"
        return
    assert "Live Internet Settings" in proc.stdout
    assert "\nVerdict: " in proc.stdout


def test_source_never_writes(tool):
    # The read-only promise, checked statically: no registry write API, no
    # write access mask, no WinINet option setter anywhere in the tool.
    with open(_TOOL, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    forbidden = {"SetValue", "SetValueEx", "DeleteValue", "DeleteKey",
                 "DeleteKeyEx", "CreateKey", "CreateKeyEx", "SaveKey", "LoadKey",
                 "KEY_WRITE", "KEY_ALL_ACCESS", "KEY_SET_VALUE",
                 "InternetSetOptionW", "InternetSetOptionA", "RegSetValueExW",
                 "RegDeleteValueW", "RegCreateKeyExW", "WinHttpSetDefaultProxyConfiguration"}
    used = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    used |= {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert not used & forbidden


# ── Verdict ──────────────────────────────────────────────────────────────────
CLEAN_LIVE = {"ProxyEnable": 0, "ProxyServer": "127.0.0.1:8881",
              "ProxyOverride": None, "AutoConfigURL": None}
SNIPER_LIVE = dict(CLEAN_LIVE, ProxyEnable=1)
RECORD = {"ProxyEnable": 0, "ProxyServer": "", "AutoConfigURLPresent": 0,
          "AppliedProxyServer": "127.0.0.1:8881", "Complete": 1}
SNIPER_PROC = {"pid": 1, "name": "SNIper_x64.exe", "command_line": "x", "is_sniper": True}
OTHER_PROC = {"pid": 2, "name": "Code.exe", "command_line": r"C:\SNIper", "is_sniper": False}


@pytest.mark.parametrize("live, record, processes, expected", [
    (CLEAN_LIVE, None, [], "CLEAN"),
    (CLEAN_LIVE, None, None, "CLEAN"),            # nothing to explain
    (CLEAN_LIVE, None, [SNIPER_PROC], "CLEAN"),   # open but stopped
    (SNIPER_LIVE, RECORD, [SNIPER_PROC, OTHER_PROC], "SNIPER ACTIVE"),
    (SNIPER_LIVE, RECORD, [OTHER_PROC], "STRANDED"),
    (SNIPER_LIVE, None, [], "STRANDED"),          # footprint without a record
    (CLEAN_LIVE, RECORD, [], "STRANDED"),         # record without a footprint
    (SNIPER_LIVE, RECORD, None, "UNKNOWN"),
    (dict(SNIPER_LIVE, ProxyServer="corp:8080"), None, [], "CLEAN"),
    (dict(SNIPER_LIVE, ProxyServer="127.0.0.1:x"), None, [], "CLEAN"),
])
def test_verdict(tool, live, record, processes, expected):
    assert tool.verdict(live, record, processes) == expected


@pytest.mark.parametrize("name, cmd, expected", [
    ("SNIper_x64.exe", None, True),
    ("SNIper_arm64.exe", r"C:\x\SNIper_arm64.exe", True),
    ("python.exe", r"python C:\SNIper\src\run_sniper.py", True),
    ("python.exe", "python -m sniper", True),
    ("pythonw.exe", "pythonw.exe -m sniper --guard 1 2 x", True),
    ("python.exe", "python -m pytest", False),
    ("python.exe", r"python C:\SNIper\tools\proxy_state.py", False),
    ("python.exe", "python -m sniper.something", False),
    ("Code.exe", r"Code.exe C:\Users\me\Desktop\SNIper", False),
    ("bash.exe", "cd /c/SNIper && python -c 'import sniper.app'", False),
    (None, None, False),
])
def test_is_sniper_process(tool, name, cmd, expected):
    assert tool.is_sniper_process(name, cmd) is expected


# ── Rendering ────────────────────────────────────────────────────────────────
def test_render_tells_absent_from_empty_and_flags_incomplete(tool):
    state = {
        "live": dict(CLEAN_LIVE, AutoConfigURL=""),
        "winhttp_ie_config": {"error": "nope"},
        "record": {"ProxyEnable": 0},
        "runonce": {"SNIperRestoreProxyEnable": "reg add ..."},
        "processes": None,
        "verdict": "UNKNOWN",
    }
    text = tool.render(state)
    assert 'AutoConfigURL   ""' in text
    assert "ProxyOverride   absent" in text
    assert "unavailable: nope" in text
    assert "(incomplete: never acted on)" in text
    assert "SNIperRestoreProxyEnable" in text
    assert text.endswith("Verdict: UNKNOWN")


def test_render_summarizes_other_processes(tool):
    state = {
        "live": SNIPER_LIVE, "record": RECORD, "runonce": {},
        "winhttp_ie_config": {"auto_detect": False, "auto_config_url": None,
                              "proxy": "127.0.0.1:8881", "proxy_bypass": None},
        "processes": [SNIPER_PROC, OTHER_PROC, dict(OTHER_PROC, pid=3)],
        "verdict": "SNIPER ACTIVE",
    }
    text = tool.render(state)
    assert "SNIper_x64.exe" in text
    assert "Code.exe" not in text
    assert "(2 other processes mention sniper; --json lists them)" in text
    assert 'Proxy           "127.0.0.1:8881"' in text
