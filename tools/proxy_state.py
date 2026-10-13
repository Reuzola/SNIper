#!/usr/bin/env python3
"""Read-only diagnostic: what is the state of this machine's proxy, and is
SNIper responsible for it?

Prints the live per-user proxy settings, what Windows reports to apps, the
SNIper restore record (and the mode it was written for), SNIper's RunOnce
values and any SNIper processes, then a one-line verdict:

  CLEAN          no restore record and no SNIper-style proxy in the live
                 settings (whether or not SNIper is open)
  SNIPER ACTIVE  a record or a SNIper-style proxy, and SNIper is running
  STRANDED (harmless: fail-open PAC)
                 SNIper's safe-mode script URL is left over and no SNIper
                 process runs; apps fall back to a direct connection, and the
                 next launch of SNIper removes it
  STRANDED       a record or a SNIper-style proxy, but no SNIper process
  UNKNOWN        a record or a SNIper-style proxy, and the process list could
                 not be read

A SNIper-style proxy is what SNIper applies: in Compatibility mode
ProxyEnable=1 with ProxyServer 127.0.0.1:<port>, in safe mode an
AutoConfigURL of the form http://127.0.0.1:<port>/sniper-<16 hex>.pac.
Another tool on a loopback port looks like the first; the record section tells
them apart.

It never writes anything: registry keys are opened for reading only, and the
only other calls are WinHttpGetIEProxyConfigForCurrentUser and a PowerShell
process query. Standard library only, Python 3.7+.

Usage:  python tools\\proxy_state.py [--json]
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import subprocess
import sys

try:
    import winreg
except ImportError:
    winreg = None

IE      = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
RESTORE = r"Software\SNIper\ProxyRestore"
RUNONCE = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
LIVE_VALUES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")

# Pre-filter: anything named SNIper* or mentioning sniper on its command line.
_PS_QUERY = (
    "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
    "Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'SNIper*' "
    "-or $_.CommandLine -like '*sniper*' } | "
    "Select ProcessId,Name,CommandLine | ConvertTo-Json")
_PS_TIMEOUT = 10
_CREATE_NO_WINDOW = 0x08000000

# What SNIper itself looks like: the built EXE, or the package run from source.
_SNIPER_NAME = re.compile(r"^sniper.*\.exe$", re.IGNORECASE)
_SNIPER_CMD  = re.compile(r"run_sniper\.py|(^|\s)-m\s+sniper(\s|$)", re.IGNORECASE)
# The static proxy SNIper applies (Compatibility mode)...
_SNIPER_PROXY = re.compile(r"^127\.0\.0\.1:\d+$")
# ...and its one-off safe-mode script URL.
_SNIPER_PAC = re.compile(r"^http://127\.0\.0\.1:\d+/sniper-[0-9a-f]{16}\.pac$")

VERDICT_HARMLESS = "STRANDED (harmless: fail-open PAC)"


# ── Registry (read only) ─────────────────────────────────────────────────────
def _plain(data):
    """A registry value as something JSON can hold."""
    if isinstance(data, bytes):
        return data.hex()
    return data


def _read_values(path):
    """{name: value} for every value of HKCU\\path, or None if it is missing."""
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return None
    try:
        values = {}
        while True:
            try:
                name, data, _ = winreg.EnumValue(k, len(values))
            except OSError:
                return values
            values[name] = _plain(data)
    finally:
        winreg.CloseKey(k)


def read_live():
    """The live values; None means absent (unlike "", an empty value)."""
    values = _read_values(IE) or {}
    by_lower = {name.lower(): value for name, value in values.items()}
    return {name: by_lower.get(name.lower()) for name in LIVE_VALUES}


def read_record():
    return _read_values(RESTORE)


def read_runonce():
    values = _read_values(RUNONCE) or {}
    return {name: value for name, value in values.items()
            if name.lower().startswith("sniper")}


# ── What Windows reports to apps ─────────────────────────────────────────────
def winhttp_ie_config():
    from ctypes import wintypes

    class IEProxyConfig(ctypes.Structure):
        # The strings are allocated by WinHTTP and must be freed with
        # GlobalFree, so they are read as raw pointers.
        _fields_ = [("fAutoDetect", wintypes.BOOL),
                    ("lpszAutoConfigUrl", ctypes.c_void_p),
                    ("lpszProxy", ctypes.c_void_p),
                    ("lpszProxyBypass", ctypes.c_void_p)]

    try:
        winhttp = ctypes.WinDLL("winhttp", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_config = winhttp.WinHttpGetIEProxyConfigForCurrentUser
        get_config.argtypes = [ctypes.POINTER(IEProxyConfig)]
        get_config.restype = wintypes.BOOL
        kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
        kernel32.GlobalFree.restype = ctypes.c_void_p
    except (OSError, AttributeError) as e:
        return {"error": str(e)}

    cfg = IEProxyConfig()
    if not get_config(ctypes.byref(cfg)):
        return {"error": "WinHttpGetIEProxyConfigForCurrentUser failed (%d)"
                % ctypes.get_last_error()}

    def take(ptr):
        if not ptr:
            return None
        try:
            return ctypes.wstring_at(ptr)
        finally:
            kernel32.GlobalFree(ptr)

    return {
        "auto_detect": bool(cfg.fAutoDetect),
        "auto_config_url": take(cfg.lpszAutoConfigUrl),
        "proxy": take(cfg.lpszProxy),
        "proxy_bypass": take(cfg.lpszProxyBypass),
    }


# ── Processes ────────────────────────────────────────────────────────────────
def is_sniper_process(name, command_line):
    return bool(_SNIPER_NAME.match(name or "") or _SNIPER_CMD.search(command_line or ""))


def list_processes():
    """SNIper-related processes, or None if they could not be listed."""
    try:
        ps = subprocess.Popen(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_QUERY],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, creationflags=_CREATE_NO_WINDOW)
    except OSError:
        return None
    try:
        out, _ = ps.communicate(timeout=_PS_TIMEOUT)
    except subprocess.TimeoutExpired:
        ps.kill()
        ps.communicate()
        return None
    if ps.returncode != 0:
        return None
    text = out.decode("utf-8", "replace").strip().lstrip("﻿")
    try:
        found = json.loads(text) if text else []
    except ValueError:
        return None
    if isinstance(found, dict):
        found = [found]
    me = {os.getpid(), ps.pid}   # this tool and its own query
    result = []
    for p in found:
        pid = p.get("ProcessId")
        if pid in me:
            continue
        name, cmd = p.get("Name"), p.get("CommandLine")
        result.append({"pid": pid, "name": name, "command_line": cmd,
                       "is_sniper": is_sniper_process(name, cmd)})
    return sorted(result, key=lambda p: p["pid"] or 0)


# ── Verdict ──────────────────────────────────────────────────────────────────
def sniper_style_proxy(live):
    """SNIper's Compatibility-mode footprint: its static proxy is enabled."""
    return (live.get("ProxyEnable") == 1
            and bool(_SNIPER_PROXY.match(str(live.get("ProxyServer") or ""))))


def sniper_pac(live):
    """SNIper's safe-mode footprint: its script URL is the setup script."""
    return bool(_SNIPER_PAC.match(str(live.get("AutoConfigURL") or "")))


def record_mode(record):
    """What the restore record says SNIper applied, in words, or None."""
    if record is None:
        return None
    if record.get("AppliedMode") == "pac":
        return "safe mode (auto-config script)"
    if record.get("AppliedMode") == "static":
        return "Compatibility mode (static proxy)"
    if "AppliedProxyServer" in record:
        return "static proxy (record from v1.1.7)"
    return "static proxy (legacy record, no footprint)"


def verdict(live, record, processes):
    static = sniper_style_proxy(live)
    pac = sniper_pac(live)
    if record is None and not static and not pac:
        return "CLEAN"
    if processes is None:
        return "UNKNOWN"
    if any(p["is_sniper"] for p in processes):
        return "SNIPER ACTIVE"
    if pac and not static:
        # A dead script URL is harmless: it can't be fetched, so apps go
        # direct. Not so if SNIper's static proxy is enabled as well.
        return VERDICT_HARMLESS
    return "STRANDED"


def collect():
    live = read_live()
    record = read_record()
    processes = list_processes()
    return {
        "live": live,
        "winhttp_ie_config": winhttp_ie_config(),
        "record": record,
        "runonce": read_runonce(),
        "processes": processes,
        "verdict": verdict(live, record, processes),
    }


# ── Output ───────────────────────────────────────────────────────────────────
def _show(value):
    if value is None:
        return "absent"
    if isinstance(value, str):
        return json.dumps(value)  # quoted, so "" and absent look different
    return str(value)


def render(state):
    out = ["SNIper proxy state (read-only)", "",
           "Live Internet Settings (HKCU)"]
    for name in LIVE_VALUES:
        line = "  %-15s %s" % (name, _show(state["live"][name]))
        if name == "AutoConfigURL" and sniper_pac(state["live"]):
            line += "  (SNIper safe-mode script)"
        out.append(line)

    out += ["", "What Windows reports to apps (WinHTTP, current user)"]
    cfg = state["winhttp_ie_config"]
    if "error" in cfg:
        out.append("  unavailable: %s" % cfg["error"])
    else:
        out.append("  %-15s %s" % ("Auto-detect", "yes" if cfg["auto_detect"] else "no"))
        for label, key in (("Setup script", "auto_config_url"), ("Proxy", "proxy"),
                           ("Bypass", "proxy_bypass")):
            value = cfg[key]
            out.append("  %-15s %s" % (label, "none" if value is None else json.dumps(value)))

    out += ["", "SNIper restore record (HKCU\\%s)" % RESTORE]
    if state["record"] is None:
        out.append("  none")
    else:
        for name in sorted(state["record"]):
            out.append("  %-21s %s" % (name, _show(state["record"][name])))
        out.append("  Mode: %s" % record_mode(state["record"]))
        if state["record"].get("Complete") != 1:
            out.append("  (incomplete: never acted on)")

    out += ["", "RunOnce values (SNIper*)"]
    if not state["runonce"]:
        out.append("  none")
    for name in sorted(state["runonce"]):
        out.append("  %s = %s" % (name, _show(state["runonce"][name])))

    out += ["", "SNIper processes"]
    processes = state["processes"]
    if processes is None:
        out.append("  unavailable")
    else:
        sniper = [p for p in processes if p["is_sniper"]]
        if not sniper:
            out.append("  none")
        for p in sniper:
            out.append("  %-7s %s  %s" % (p["pid"], p["name"], json.dumps(p["command_line"])))
        others = len(processes) - len(sniper)
        if others:
            # Editors, shells and the like whose command line merely contains
            # a path with "sniper" in it.
            out.append("  (%d other process%s mention sniper; --json lists them)"
                       % (others, "" if others == 1 else "es"))

    out += ["", "Verdict: %s" % state["verdict"]]
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Show the proxy state SNIper cares about. Never writes anything.")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)
    try:
        sys.stdout.reconfigure(errors="backslashreplace")
    except (AttributeError, ValueError):
        pass
    if winreg is None or os.name != "nt":
        print("Windows only")
        return 0
    state = collect()
    if args.json:
        print(json.dumps(state, indent=2, sort_keys=True))
    else:
        print(render(state))
    return 0


if __name__ == "__main__":
    sys.exit(main())
