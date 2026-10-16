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
KEYS = {"live", "winhttp_ie_config", "record", "owner", "guardians", "runonce",
        "processes", "verdict"}
HARMLESS = "STRANDED (harmless: fail-open PAC)"
GUARDED = "SNIPER ACTIVE (guarded)"
UNGUARDED = "SNIPER ACTIVE (no guardian)"
STALE = "CLEAN (stale record — removed on next launch)"
VERDICTS = {"CLEAN", STALE, GUARDED, UNGUARDED, "STRANDED", HARMLESS, "UNKNOWN"}


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
    assert state["verdict"] in VERDICTS
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
PAC_URL = "http://127.0.0.1:8881/sniper-0123456789abcdef.pac"
PAC_LIVE = dict(CLEAN_LIVE, ProxyServer="", AutoConfigURL=PAC_URL)
PAC_RECORD = dict(RECORD, AppliedMode="pac", AppliedAutoConfigURL=PAC_URL)
# Safe mode as it is now: the script next to a manual proxy bypassing every host.
SAFE_LIVE = dict(PAC_LIVE, ProxyEnable=1, ProxyServer="127.0.0.1:8881",
                 ProxyOverride="*")
SAFE_RECORD = dict(PAC_RECORD, ProxyOverridePresent=0, AppliedManualProxy=1)
SNIPER_PROC = {"pid": 1, "name": "SNIper_x64.exe", "command_line": "x", "is_sniper": True}
OTHER_PROC = {"pid": 2, "name": "Code.exe", "command_line": r"C:\SNIper", "is_sniper": False}


@pytest.mark.parametrize("live, record, processes, expected", [
    (CLEAN_LIVE, None, [], "CLEAN"),
    (CLEAN_LIVE, None, None, "CLEAN"),            # nothing to explain
    (CLEAN_LIVE, None, [SNIPER_PROC], "CLEAN"),   # open but stopped
    # A v1.1.7-style record has no session, so nothing can be guarding it.
    (SNIPER_LIVE, RECORD, [SNIPER_PROC, OTHER_PROC], UNGUARDED),
    (SNIPER_LIVE, RECORD, [OTHER_PROC], "STRANDED"),
    (SNIPER_LIVE, None, [], "STRANDED"),          # footprint without a record
    (CLEAN_LIVE, RECORD, [], "STRANDED"),         # record without a footprint
    (SNIPER_LIVE, RECORD, None, "UNKNOWN"),
    (dict(SNIPER_LIVE, ProxyServer="corp:8080"), None, [], "CLEAN"),
    (dict(SNIPER_LIVE, ProxyServer="127.0.0.1:x"), None, [], "CLEAN"),
    # Safe mode: the script URL is the footprint.
    (PAC_LIVE, PAC_RECORD, [SNIPER_PROC], UNGUARDED),
    (PAC_LIVE, PAC_RECORD, [OTHER_PROC], HARMLESS),
    (PAC_LIVE, None, [], HARMLESS),               # footprint without a record
    (PAC_LIVE, PAC_RECORD, None, "UNKNOWN"),
    (CLEAN_LIVE, PAC_RECORD, [], "STRANDED"),     # record without a footprint
    # A manual proxy of the user's own is what a dead script falls back to.
    (dict(PAC_LIVE, ProxyEnable=1, ProxyServer="corp:8080"), None, [], HARMLESS),
    # SNIper's static proxy is enabled too: that one is not harmless...
    (dict(PAC_LIVE, ProxyEnable=1, ProxyServer="127.0.0.1:8881"), PAC_RECORD, [],
     "STRANDED"),
    (dict(PAC_LIVE, ProxyEnable=1, ProxyServer="127.0.0.1:8881",
          ProxyOverride="<local>"), PAC_RECORD, [], "STRANDED"),
    # ...unless it bypasses every host, as safe mode's own manual proxy does.
    (SAFE_LIVE, SAFE_RECORD, [OTHER_PROC], HARMLESS),
    (SAFE_LIVE, None, [], HARMLESS),
    (SAFE_LIVE, SAFE_RECORD, [SNIPER_PROC], UNGUARDED),
    # The bypass list alone is no footprint at all.
    (dict(CLEAN_LIVE, ProxyOverride="*"), None, [], "CLEAN"),
    # Without the script, SNIper's static proxy is what apps use: stranded.
    (dict(SAFE_LIVE, AutoConfigURL=None), None, [], "STRANDED"),
    # Setup scripts that are not SNIper's.
    (dict(CLEAN_LIVE, AutoConfigURL="http://127.0.0.1:8881/proxy.pac"), None, [], "CLEAN"),
    (dict(CLEAN_LIVE, AutoConfigURL="http://127.0.0.1:8881/sniper-0123.pac"), None, [],
     "CLEAN"),
    (dict(CLEAN_LIVE, AutoConfigURL=PAC_URL.upper()), None, [], "CLEAN"),
    (dict(CLEAN_LIVE, AutoConfigURL=PAC_URL.replace("http:", "https:")), None, [], "CLEAN"),
    (dict(CLEAN_LIVE, AutoConfigURL=PAC_URL.replace("127.0.0.1", "localhost")), None, [],
     "CLEAN"),
    (dict(CLEAN_LIVE, AutoConfigURL=PAC_URL + "?x"), None, [], "CLEAN"),
    (dict(CLEAN_LIVE, AutoConfigURL="http://corp/p.pac"), None, [], "CLEAN"),
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


@pytest.mark.parametrize("record, expected", [
    (None, None),
    (PAC_RECORD, "safe mode (auto-config script)"),
    (SAFE_RECORD, "safe mode (auto-config script + manual proxy bypassing every host)"),
    (dict(RECORD, AppliedMode="static"), "Compatibility mode (static proxy)"),
    (RECORD, "static proxy (record from v1.1.7)"),
    ({"ProxyEnable": 1, "ProxyServer": "corp:8080", "Complete": 1},
     "static proxy (legacy record, no footprint)"),
])
def test_record_mode(tool, record, expected):
    assert tool.record_mode(record) == expected


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


def test_render_marks_the_safe_mode_script_and_the_record_mode(tool):
    state = {
        "live": PAC_LIVE, "record": PAC_RECORD, "runonce": {},
        "winhttp_ie_config": {"auto_detect": True, "auto_config_url": PAC_URL,
                              "proxy": None, "proxy_bypass": None},
        "processes": [], "verdict": HARMLESS,
    }
    text = tool.render(state)
    assert ('AutoConfigURL   "%s"  (SNIper safe-mode script)' % PAC_URL) in text
    assert "  Mode: safe mode (auto-config script)" in text
    assert text.endswith("Verdict: " + HARMLESS)
    # Another tool's setup script gets no such label.
    state["live"] = dict(CLEAN_LIVE, AutoConfigURL="http://corp/p.pac")
    assert "SNIper safe-mode script" not in tool.render(state)


def test_render_marks_the_bypass_all_list(tool):
    state = {
        "live": SAFE_LIVE, "record": SAFE_RECORD, "runonce": {},
        "winhttp_ie_config": {"auto_detect": False, "auto_config_url": PAC_URL,
                              "proxy": "127.0.0.1:8881", "proxy_bypass": "*"},
        "processes": [], "verdict": HARMLESS,
    }
    text = tool.render(state)
    assert 'ProxyOverride   "*"  (bypasses every host)' in text
    assert ("  Mode: safe mode (auto-config script + manual proxy bypassing "
            "every host)") in text
    state["live"] = dict(SAFE_LIVE, ProxyOverride="<local>")
    assert "bypasses every host)" not in tool.render(state).split("Mode:")[0]


# ── Owner and guardian (Step 3) ──────────────────────────────────────────────
SID = "0123456789abcdef"
OWNED_RECORD = dict(PAC_RECORD, OwnerPid=4242, OwnerCreateTime=133700000000000000,
                    SessionId=SID)
APP_SRC = {"pid": 4242, "name": "python.exe", "is_sniper": True,
           "command_line": r"python C:\SNIper\src\run_sniper.py"}
GUARD = {"pid": 77, "name": "python.exe", "is_sniper": True,
         "command_line": "python.exe -m sniper --guard 4242 133700000000000000 " + SID}
GUARD_EXE = {"pid": 78, "name": "SNIper_arm64.exe", "is_sniper": True,
             "command_line": r'"C:\x\SNIper_arm64.exe" --guard 1 2 ' + SID}
OTHER_GUARD = dict(GUARD, pid=79, command_line=GUARD["command_line"].replace(
    SID, "fedcba9876543210"))
SPAWNER = dict(GUARD, pid=80, command_line=GUARD["command_line"].replace(
    "--guard", "--spawn-guard"))
SELFTEST = {"pid": 81, "name": "python.exe", "is_sniper": True,
            "command_line": "python -m sniper --selftest-owner safe"}


@pytest.mark.parametrize("live, record, processes, expected", [
    (PAC_LIVE, OWNED_RECORD, [APP_SRC, GUARD], GUARDED),
    (PAC_LIVE, OWNED_RECORD, [SNIPER_PROC, GUARD_EXE], GUARDED),
    (SNIPER_LIVE, dict(RECORD, SessionId=SID), [SNIPER_PROC, GUARD], GUARDED),
    (PAC_LIVE, OWNED_RECORD, [APP_SRC], UNGUARDED),
    (PAC_LIVE, OWNED_RECORD, [APP_SRC, OTHER_GUARD], UNGUARDED),  # another session
    (PAC_LIVE, OWNED_RECORD, [APP_SRC, SPAWNER], UNGUARDED),      # not yet started
    (PAC_LIVE, None, [APP_SRC, GUARD], UNGUARDED),                # nothing to guard
    # Helpers alone are not SNIper running.
    (PAC_LIVE, OWNED_RECORD, [GUARD], HARMLESS),                  # mid-restore
    (SNIPER_LIVE, dict(RECORD, SessionId=SID), [GUARD, SPAWNER], "STRANDED"),
    (PAC_LIVE, OWNED_RECORD, [SELFTEST], HARMLESS),               # a test's stand-in
], ids=["guarded", "guarded-exe", "guarded-compat", "no-guardian", "other-session",
        "spawner-only", "no-record", "guardian-alone", "helpers-alone", "selftest"])
def test_verdict_with_guardians(tool, live, record, processes, expected):
    assert tool.verdict(live, record, processes) == expected


@pytest.mark.parametrize("proc, role", [
    (SNIPER_PROC, "app"), (APP_SRC, "app"), (GUARD, "guardian"), (GUARD_EXE, "guardian"),
    (SPAWNER, "spawner"), (SELFTEST, "selftest"), (OTHER_PROC, None),
    ({"name": "python.exe", "command_line": "python -m pytest --guard 1 2 " + SID}, None),
    ({"name": "SNIper_x64.exe", "command_line": "SNIper_x64.exe --guarded"}, "app"),
])
def test_process_role(tool, proc, role):
    assert tool.process_role(proc["name"], proc["command_line"]) == role


def test_guardians_are_matched_on_their_exact_arguments(tool):
    lookalike = dict(GUARD, pid=90, command_line="python -m sniper --guard x y " + SID)
    shell = {"pid": 91, "name": "bash.exe", "is_sniper": False,
             "command_line": "bash -c 'python -m sniper --guard 1 2 %s'" % SID}
    procs = [APP_SRC, GUARD, GUARD_EXE, OTHER_GUARD, SPAWNER, lookalike, shell]
    assert tool.guardians(procs, SID) == [77, 78]
    assert tool.guardians(procs, None) == []
    assert tool.guardians(None, SID) == []


def test_owner_info(tool, monkeypatch):
    seen = []
    monkeypatch.setattr(tool, "process_alive", lambda pid, ct: seen.append((pid, ct)) or True)
    assert tool.owner_info(None) is None
    assert tool.owner_info(RECORD) is None  # a v1.1.7 record names no owner
    assert tool.owner_info(OWNED_RECORD) == {
        "pid": 4242, "create_time": 133700000000000000, "session_id": SID, "alive": True}
    assert seen == [(4242, 133700000000000000)]


def test_render_shows_owner_guardian_and_roles(tool):
    state = {
        "live": PAC_LIVE, "record": OWNED_RECORD, "runonce": {},
        "owner": {"pid": 4242, "create_time": 1, "session_id": SID, "alive": True},
        "guardians": [77],
        "winhttp_ie_config": {"error": "x"},
        "processes": [APP_SRC, GUARD], "verdict": GUARDED,
    }
    text = tool.render(state)
    assert "  Owner: PID 4242 (running), session %s" % SID in text
    assert "Safety guard (guardian of session %s)\n  PID 77" % SID in text
    assert "python.exe  [guardian]" in text
    assert text.endswith("Verdict: " + GUARDED)
    state.update(guardians=[], owner=dict(state["owner"], alive=False),
                 processes=[APP_SRC], verdict=UNGUARDED)
    text = tool.render(state)
    assert "(not running)" in text
    assert "Safety guard (guardian of session %s)\n  none" % SID in text
    state.update(record=RECORD, owner=None)
    text = tool.render(state)
    assert "Owner: not recorded (a record from before v1.2)" in text
    assert "Safety guard" not in text


# ── A stale record (Step 4) ──────────────────────────────────────────────────
# What the sign-in safety net leaves after it ran: a complete static record
# whose genuine values are live again, and no SNIper anywhere.
GENUINE_LIVE = {"ProxyEnable": 1, "ProxyServer": "corp:8080", "ProxyOverride": None,
                "AutoConfigURL": "http://corp/p.pac"}
STALE_RECORD = dict(OWNED_RECORD, AppliedMode="static", ProxyEnable=1,
                    ProxyServer="corp:8080", AutoConfigURLPresent=1,
                    AutoConfigURL="http://corp/p.pac")
del STALE_RECORD["AppliedAutoConfigURL"]


@pytest.mark.parametrize("live, record, processes, expected", [
    (GENUINE_LIVE, STALE_RECORD, [], STALE),
    (GENUINE_LIVE, STALE_RECORD, [OTHER_PROC, GUARD], STALE),      # helpers aren't SNIper
    (CLEAN_LIVE, dict(RECORD, ProxyServer="127.0.0.1:8881"), [], STALE),   # v1.1.7
    (dict(CLEAN_LIVE, ProxyEnable=None), RECORD, [], "STRANDED"),   # "" vs 127.0.0.1:8881
    (dict(CLEAN_LIVE, ProxyServer="", ProxyEnable=None), RECORD, [], STALE),  # absent = 0
    ({"ProxyEnable": 0, "ProxyServer": "", "ProxyOverride": None, "AutoConfigURL": None},
     {"ProxyEnable": 0, "ProxyServer": "", "Complete": 1}, [], STALE),       # legacy
    (dict(PAC_LIVE, AutoConfigURL=None), PAC_RECORD, [], STALE),    # safe mode, URL gone
    # Not stale: SNIper runs, the record is incomplete, the state is unknown,
    # or the live values differ from the genuine ones in any way.
    (GENUINE_LIVE, STALE_RECORD, [SNIPER_PROC], UNGUARDED),
    (GENUINE_LIVE, dict(STALE_RECORD, Complete=0), [], "STRANDED"),
    (GENUINE_LIVE, {k: v for k, v in STALE_RECORD.items() if k != "Complete"}, [],
     "STRANDED"),
    (GENUINE_LIVE, STALE_RECORD, None, "UNKNOWN"),
    (dict(GENUINE_LIVE, AutoConfigURL=""), STALE_RECORD, [], "STRANDED"),
    (dict(GENUINE_LIVE, AutoConfigURL=None), STALE_RECORD, [], "STRANDED"),
    (dict(GENUINE_LIVE, ProxyEnable=0), STALE_RECORD, [], "STRANDED"),
    (dict(GENUINE_LIVE, ProxyEnable="x"), STALE_RECORD, [], "STRANDED"),
    (dict(GENUINE_LIVE, ProxyServer="corp:8081"), STALE_RECORD, [], "STRANDED"),
    (dict(GENUINE_LIVE, AutoConfigURL="http://corp/other.pac"), STALE_RECORD, [],
     "STRANDED"),
    (dict(CLEAN_LIVE, ProxyServer="", AutoConfigURL=""), dict(RECORD, ProxyServer=""), [],
     "STRANDED"),                                                   # empty is not absent
    # Garbage in the record reads as winproxy reads it: 0, "" and no script.
    (dict(CLEAN_LIVE, ProxyServer=""), dict(RECORD, ProxyEnable="zz", ProxyServer=5), [],
     STALE),
    (dict(CLEAN_LIVE, ProxyServer=""), dict(RECORD, ProxyServer="", AutoConfigURLPresent=1),
     [], STALE),                                                    # present, but no URL
], ids=["static", "with-helpers", "v117", "v117-differs", "absent-enable", "legacy",
        "safe-mode", "sniper-runs", "incomplete", "no-complete", "unknown",
        "empty-vs-genuine-pac", "absent-vs-genuine-pac", "enable-differs",
        "unreadable-enable", "server-differs", "pac-differs", "empty-vs-absent",
        "garbage-record", "present-flag-without-url"])
def test_a_record_the_live_settings_already_match_is_stale(tool, live, record,
                                                           processes, expected):
    assert tool.verdict(live, record, processes) == expected


# A safe-mode record with the manual proxy also holds the genuine bypass list,
# which winproxy's "already" check compares too.
BACK_LIVE = dict(CLEAN_LIVE, ProxyServer="")   # SAFE_RECORD's genuine values


@pytest.mark.parametrize("live, record, expected", [
    (BACK_LIVE, SAFE_RECORD, STALE),
    (dict(BACK_LIVE, ProxyOverride="<local>"),
     dict(SAFE_RECORD, ProxyOverridePresent=1, ProxyOverride="<local>"), STALE),
    (dict(BACK_LIVE, ProxyOverride=""),
     dict(SAFE_RECORD, ProxyOverridePresent=1, ProxyOverride=7), STALE),   # garbage = ""
    (BACK_LIVE, dict(SAFE_RECORD, ProxyOverridePresent=1), STALE),     # present, no value
    # Not stale: SNIper's "*" is still there, or the genuine list isn't back.
    (dict(BACK_LIVE, ProxyOverride="*"), SAFE_RECORD, "STRANDED"),
    (BACK_LIVE, dict(SAFE_RECORD, ProxyOverridePresent=1, ProxyOverride="<local>"),
     "STRANDED"),
    (dict(BACK_LIVE, ProxyOverride=""), SAFE_RECORD, "STRANDED"),      # empty is not absent
    # Only safe mode writes the list, so only a safe-mode record is judged by it.
    (dict(GENUINE_LIVE, ProxyOverride="*"), dict(STALE_RECORD, ProxyOverridePresent=0),
     STALE),
], ids=["absent", "recorded", "garbage-record", "present-flag-without-value",
        "bypass-all-left", "genuine-list-missing", "empty-vs-absent", "static-ignores-it"])
def test_a_safe_mode_record_is_stale_only_with_its_bypass_list_back(tool, live, record,
                                                                    expected):
    assert tool.verdict(live, record, []) == expected


def test_render_marks_a_stale_record(tool):
    state = {"live": GENUINE_LIVE, "record": STALE_RECORD, "runonce": {}, "owner": None,
             "guardians": [], "winhttp_ie_config": {"error": "x"}, "processes": [],
             "verdict": STALE}
    text = tool.render(state)
    assert "(stale: the live settings already hold these genuine values)" in text
    assert text.endswith("Verdict: " + STALE)
    state["live"] = dict(GENUINE_LIVE, ProxyEnable=0)
    assert "(stale:" not in tool.render(state)


@pytest.mark.slow
@pytest.mark.skipif(not IS_WINDOWS, reason="main() prints 'Windows only' elsewhere")
def test_the_stale_verdict_survives_a_narrow_console_encoding():
    # The em dash must never crash the tool on a cp437 console: main() is run
    # in a subprocess on such a stdout, with collect() replaced by that state.
    proc = subprocess.run(
        [sys.executable, "-c",
         "import importlib.util, sys; s = importlib.util.spec_from_file_location('t', sys.argv[1]);"
         "m = importlib.util.module_from_spec(s); s.loader.exec_module(m);"
         "m.collect = lambda: {'live': {'ProxyEnable': 0, 'ProxyServer': '', 'ProxyOverride': None,"
         " 'AutoConfigURL': None}, 'record': None, 'runonce': {}, 'owner': None, 'guardians': [],"
         " 'winhttp_ie_config': {'error': 'x'}, 'processes': [], 'verdict': m.VERDICT_STALE};"
         "sys.exit(m.main([]))", _TOOL],
        capture_output=True, timeout=60, env=dict(os.environ, PYTHONIOENCODING="cp437"))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.rstrip().endswith(b"Verdict: CLEAN (stale record \\u2014 removed on next launch)")


@pytest.mark.skipif(not IS_WINDOWS, reason="Win32 process queries")
def test_process_alive_on_real_processes(tool):
    import sniper.procutil as procutil
    pid, created = procutil.process_identity()
    assert tool.process_alive(pid, created) is True
    assert tool.process_alive(pid, None) is True        # an older record
    assert tool.process_alive(pid, created + 1) is False  # a PID reused
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait(30)
    gone = p.pid
    del p
    assert tool.process_alive(gone, 1) is False
    assert tool.process_alive(None, 1) is None
    assert tool.process_alive(0, 1) is None
