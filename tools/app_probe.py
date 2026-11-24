#!/usr/bin/env python3
"""Read-only diagnostic: does an app go through SNIper, or around it?

Watches the TCP connections of every process with one of the given names and
says, per process, which went through SNIper's port and which straight to a
remote host. For "app X doesn't work with SNIper": a direct connection while
SNIper runs means that part of the app found no Windows proxy, or ignored it;
no direct connection means the trouble is elsewhere.

  Discord.exe, say, is one name but many processes. The role column tells them
  apart: an Electron or Chromium app does its web traffic in "NetworkService",
  which follows the PAC script, while a native part of it (Discord's updater)
  connects from the main process and reads the proxy its own way.

Each connection is one of
  via SNIper     to 127.0.0.1:<SNIper's port>
  local          to a loopback, private or link-local address, which is not
                 supposed to go through SNIper
  DIRECT         to anything else, on any port: around SNIper

Connections are sampled, about ten times a second, so a very short one can be
missed; a connection attempt that hangs (SYN_SENT, as to a blocked host) is
not. Start the app after this tool to see its startup. TCP only: voice and
HTTP/3 use UDP, which never goes through an HTTP proxy.

It never writes anything: registry keys are opened for reading only, and the
only other calls list processes and TCP connections (and, once at the end, ask
PowerShell for the command lines the roles come from). Standard library only,
Python 3.7+.

Usage:  python tools\\app_probe.py NAME [NAME ...] [--seconds N] [--port P] [--json]
        python tools\\app_probe.py Discord.exe --seconds 60
"""
from __future__ import annotations

import argparse
import ctypes
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time

try:
    import winreg
except ImportError:
    winreg = None

IE = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
DEFAULT_PORT = 8881
_INTERVAL = 0.1
_PS_TIMEOUT = 20
_CREATE_NO_WINDOW = 0x08000000

VIA, LOCAL, DIRECT = "via SNIper", "local", "DIRECT"
STATES = {1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED",
          6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING",
          10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB"}


# ── SNIper's port (registry, read only) ──────────────────────────────────────
def sniper_port():
    """The port the live proxy settings name on 127.0.0.1, or None: from the
    manual proxy if it is on, else from a SNIper script URL."""
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, IE, 0, winreg.KEY_READ)
    except (AttributeError, OSError):
        return None
    try:
        def read(name):
            try:
                return winreg.QueryValueEx(k, name)[0]
            except OSError:
                return None
        return port_of(read("ProxyEnable"), read("ProxyServer"), read("AutoConfigURL"))
    finally:
        winreg.CloseKey(k)


def port_of(enable, server, script):
    m = re.match(r"^127\.0\.0\.1:(\d+)$", str(server or "")) if enable == 1 else None
    m = m or re.match(r"^http://127\.0\.0\.1:(\d+)/sniper-[0-9a-f]{16}\.pac$",
                      str(script or ""))
    return int(m.group(1)) if m else None


# ── Classification ───────────────────────────────────────────────────────────
def classify(address, port, sniper):
    """What a connection to address:port is, given SNIper's port."""
    ip = ipaddress.ip_address(address)
    mapped = getattr(ip, "ipv4_mapped", None)
    ip = mapped or ip
    if ip.is_loopback:
        return VIA if port == sniper else LOCAL
    if ip.is_private or ip.is_link_local or ip.is_unspecified:
        return LOCAL
    return DIRECT


def role(command_line):
    """What kind of process a command line starts, as Chromium-based apps
    mark theirs, or "main"; "?" without one."""
    if not command_line:
        return "?"
    m = re.search(r"--utility-sub-type=(\S+)", command_line)
    if m:
        return m.group(1).split(".")[-1]
    m = re.search(r"--type=(\S+)", command_line)
    return m.group(1) if m else "main"


# ── Win32 (read only) ────────────────────────────────────────────────────────
def _structures():
    from ctypes import wintypes

    class ProcessEntry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("pid", wintypes.DWORD), ("heap", ctypes.c_size_t),
                    ("module", wintypes.DWORD), ("threads", wintypes.DWORD),
                    ("parent", wintypes.DWORD), ("priority", ctypes.c_long),
                    ("flags", wintypes.DWORD), ("exe", ctypes.c_wchar * 260)]

    class Tcp4(ctypes.Structure):
        _fields_ = [("state", wintypes.DWORD), ("local", wintypes.DWORD),
                    ("local_port", wintypes.DWORD), ("remote", wintypes.DWORD),
                    ("remote_port", wintypes.DWORD), ("pid", wintypes.DWORD)]

    class Tcp6(ctypes.Structure):
        _fields_ = [("local", ctypes.c_ubyte * 16), ("local_scope", wintypes.DWORD),
                    ("local_port", wintypes.DWORD), ("remote", ctypes.c_ubyte * 16),
                    ("remote_scope", wintypes.DWORD), ("remote_port", wintypes.DWORD),
                    ("state", wintypes.DWORD), ("pid", wintypes.DWORD)]

    return wintypes, ProcessEntry, Tcp4, Tcp6


class System:
    """The two lists this tool samples. Tests pass something simpler."""

    def __init__(self):
        wintypes, self._entry, self._tcp4, self._tcp6 = _structures()
        self._dword = wintypes.DWORD
        self._k = k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        k.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        for fn in (k.Process32FirstW, k.Process32NextW):
            fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(self._entry)]
            fn.restype = wintypes.BOOL
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        self._tcp = ctypes.WinDLL("iphlpapi").GetExtendedTcpTable
        self._tcp.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
                              wintypes.BOOL, wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
        self._tcp.restype = wintypes.DWORD

    def processes(self):
        """{pid: image name} of every process."""
        snapshot = self._k.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
        if snapshot in (None, ctypes.c_void_p(-1).value):
            return {}
        try:
            entry = self._entry()
            entry.dwSize = ctypes.sizeof(entry)
            found, more = {}, self._k.Process32FirstW(snapshot, ctypes.byref(entry))
            while more:
                found[entry.pid] = entry.exe
                more = self._k.Process32NextW(snapshot, ctypes.byref(entry))
            return found
        finally:
            self._k.CloseHandle(snapshot)

    def connections(self):
        """[(pid, remote address, remote port, state, local port)], IPv4 and
        IPv6, without listening sockets."""
        out = []
        for family, row in ((2, self._tcp4), (23, self._tcp6)):  # AF_INET, AF_INET6
            size = self._dword(0)
            self._tcp(None, ctypes.byref(size), False, family, 5, 0)  # ..._OWNER_PID_ALL
            buf = ctypes.create_string_buffer(size.value + 16384)
            size.value = len(buf)
            if self._tcp(buf, ctypes.byref(size), False, family, 5, 0):
                continue
            count = struct.unpack_from("<I", buf, 0)[0]
            rows = ctypes.cast(ctypes.byref(buf, 4), ctypes.POINTER(row * count)).contents
            for r in rows:
                if r.state == 2:
                    continue
                address = (socket.inet_ntoa(struct.pack("<I", r.remote)) if family == 2
                           else socket.inet_ntop(socket.AF_INET6, bytes(r.remote)))
                out.append((r.pid, address, socket.ntohs(r.remote_port & 0xFFFF),
                            STATES.get(r.state, str(r.state)),
                            socket.ntohs(r.local_port & 0xFFFF)))
        return out

    def command_lines(self, pids):
        """{pid: command line} for those still running; {} if PowerShell can't
        be asked."""
        if not pids:
            return {}
        query = ("[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
                 "Get-CimInstance Win32_Process -Filter \"%s\" | "
                 "Select ProcessId,CommandLine | ConvertTo-Json"
                 % " OR ".join("ProcessId=%d" % pid for pid in pids))
        try:
            done = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", query],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=_PS_TIMEOUT,
                creationflags=_CREATE_NO_WINDOW)
            text = done.stdout.decode("utf-8", "replace").strip().lstrip("﻿")
            found = json.loads(text) if text else []
        except (OSError, ValueError, subprocess.SubprocessError):
            return {}
        if isinstance(found, dict):
            found = [found]
        return {p["ProcessId"]: p.get("CommandLine") for p in found}


# ── Watching ─────────────────────────────────────────────────────────────────
def wanted_names(names):
    """The image names asked for, lower case, with .exe added if it is missing."""
    return {n.lower() if n.lower().endswith(".exe") else n.lower() + ".exe" for n in names}


def probe(names, seconds, system, clock=time.monotonic, sleep=time.sleep):
    """Sample for seconds (0: once): ({pid: name}, {(pid, address, port):
    {first, last, sockets, states}}) of everything seen."""
    names = wanted_names(names)
    seen, conns = {}, {}
    start = clock()
    while True:
        now = clock() - start
        ours = {pid: exe for pid, exe in system.processes().items() if exe.lower() in names}
        seen.update(ours)
        for pid, address, port, state, local_port in system.connections():
            if pid not in ours or not port:
                continue
            c = conns.setdefault((pid, address, port), {
                "first": now, "last": now, "sockets": set(), "states": set()})
            c["last"] = now
            c["sockets"].add(local_port)
            c["states"].add(state)
        if now >= seconds:
            return seen, conns
        sleep(_INTERVAL)


def collect(names, port, seconds, system=None, **timing):
    """{"port", "port_assumed", "seconds", "processes": [{pid, name, role}],
    "connections": [{pid, name, role, remote, class, sockets, first, last,
    states}]}. port is SNIper's, None if nothing tells: then its default one
    is assumed."""
    system = system or System()
    sniper = port or DEFAULT_PORT
    seen, conns = probe(names, seconds, system, **timing)
    lines = system.command_lines(sorted(seen))
    roles = {pid: role(lines.get(pid)) for pid in seen}
    rows = [{"pid": pid, "name": seen[pid], "role": roles[pid],
             "remote": ("[%s]:%d" if ":" in address else "%s:%d") % (address, port),
             "class": classify(address, port, sniper), "sockets": len(c["sockets"]),
             "first": round(c["first"], 1), "last": round(c["last"], 1),
             "states": sorted(c["states"])}
            for (pid, address, port), c in conns.items()]
    rows.sort(key=lambda r: (r["first"], r["pid"], r["remote"]))
    return {"port": sniper, "port_assumed": not port, "seconds": seconds,
            "connections": rows, "processes": [{"pid": pid, "name": seen[pid], "role": roles[pid]}
                          for pid in sorted(seen)]}


# ── Output ───────────────────────────────────────────────────────────────────
def verdict(result):
    """One line: which way the app's connections went."""
    if not result["processes"]:
        return "No such process was running."
    counts = {kind: sum(r["sockets"] for r in result["connections"] if r["class"] == kind)
              for kind in (VIA, LOCAL, DIRECT)}
    if not counts[VIA] and not counts[DIRECT]:
        return "No connection to the internet was seen."
    if not counts[DIRECT]:
        return "Every connection to the internet went through SNIper (%d)." % counts[VIA]
    who = sorted({"%s [%s]" % (r["name"], r["role"]) for r in result["connections"]
                  if r["class"] == DIRECT})
    return "%d connection%s went around SNIper, from %s; %d went through it." % (
        counts[DIRECT], "" if counts[DIRECT] == 1 else "s", ", ".join(who), counts[VIA])


def render(result):
    out = ["App probe (read-only), %s" % (
        "one look" if not result["seconds"] else "%g seconds" % result["seconds"]),
        "SNIper's port: %d%s" % (result["port"], "  (assumed: not in the proxy settings; "
                                 "is SNIper running?)" if result["port_assumed"] else ""),
        "", "Processes"]
    if not result["processes"]:
        out.append("  none")
    for p in result["processes"]:
        out.append("  %-7d %-24s %s" % (p["pid"], p["name"], p["role"]))
    out += ["", "Connections"]
    if not result["connections"]:
        out.append("  none")
    for r in result["connections"]:
        out.append("  %5.1fs  %-7d %-16s %-10s %-28s %s%s" % (
            r["first"], r["pid"], r["role"], r["class"], r["remote"],
            "/".join(r["states"]), "" if r["sockets"] == 1 else "  x%d" % r["sockets"]))
    out += ["", verdict(result)]
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Show which of an app's TCP connections go through SNIper. "
                    "Never writes anything.")
    parser.add_argument("names", nargs="+", metavar="NAME",
                        help="process image name, such as Discord.exe")
    parser.add_argument("--seconds", type=float, default=15.0,
                        help="how long to watch (default 15; 0 looks once)")
    parser.add_argument("--port", type=int, default=None,
                        help="SNIper's port (default: from the proxy settings, "
                             "else %d)" % DEFAULT_PORT)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)
    try:
        sys.stdout.reconfigure(errors="backslashreplace")
    except (AttributeError, ValueError):
        pass
    if winreg is None or os.name != "nt":
        print("Windows only")
        return 0
    result = collect(args.names, args.port or sniper_port(), args.seconds)
    print(json.dumps(result, indent=2) if args.json else render(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
