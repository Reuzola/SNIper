"""Tests for tools/app_probe.py, the read-only "does this app go through SNIper?"
diagnostic: classification, sampling and output on synthetic systems, and one
run against this machine's real tables.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading

import pytest

from sniper.compat import IS_WINDOWS

_TOOL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "..", "tools", "app_probe.py"))


@pytest.fixture(scope="module")
def tool():
    spec = importlib.util.spec_from_file_location("app_probe", _TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeSystem:
    """Plays back samples: each is (processes, connections); the last repeats."""

    def __init__(self, *samples, lines=None):
        self.samples = list(samples)
        self.lines = lines or {}
        self.current = None

    def processes(self):
        self.current = self.samples.pop(0) if len(self.samples) > 1 else self.samples[0]
        return self.current[0]

    def connections(self):
        return self.current[1]

    def command_lines(self, pids):
        return {pid: self.lines[pid] for pid in pids if pid in self.lines}


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


MAIN, NET = 10, 11
DISCORD = {MAIN: "Discord.exe", NET: "Discord.exe", 99: "other.exe"}
LINES = {MAIN: r'"C:\x\Discord.exe"',
         NET: r'"C:\x\Discord.exe" --type=utility '
              "--utility-sub-type=network.mojom.NetworkService --lang=tr"}
VIA_NET = (NET, "127.0.0.1", 8881, "ESTABLISHED", 50001)
AROUND = (MAIN, "195.175.254.2", 443, "SYN_SENT", 50002)
OTHERS = (99, "1.2.3.4", 443, "ESTABLISHED", 50003)


def run(tool, *samples, names=("discord",), port=8881, seconds=0, lines=LINES):
    clock = Clock()
    return tool.collect(names, port, seconds, FakeSystem(*samples, lines=lines),
                        clock=clock, sleep=clock.sleep)


# ── Classification ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("address, port, expected", [
    ("127.0.0.1", 8881, "via SNIper"),
    ("::1", 8881, "via SNIper"),
    ("::ffff:127.0.0.1", 8881, "via SNIper"),
    ("127.0.0.1", 8882, "local"),        # another local service
    ("192.168.1.1", 443, "local"), ("10.0.0.5", 443, "local"),
    ("172.16.0.1", 443, "local"), ("169.254.1.1", 443, "local"),
    ("fe80::1", 443, "local"), ("0.0.0.0", 1, "local"),
    ("195.175.254.2", 443, "DIRECT"), ("172.32.0.1", 443, "DIRECT"),
    ("2606:4700::1111", 443, "DIRECT"), ("8.8.8.8", 8881, "DIRECT"),
])
def test_classify(tool, address, port, expected):
    assert tool.classify(address, port, 8881) == expected


@pytest.mark.parametrize("line, expected", [
    (LINES[MAIN], "main"), (LINES[NET], "NetworkService"), (None, "?"), ("", "?"),
    ("Discord.exe --type=renderer --x", "renderer"), ("Update.exe --processStart D.exe", "main"),
])
def test_role(tool, line, expected):
    assert tool.role(line) == expected


@pytest.mark.parametrize("enable, server, script, expected", [
    (1, "127.0.0.1:8881", None, 8881),
    (0, "127.0.0.1:8881", "http://127.0.0.1:9999/sniper-0123456789abcdef.pac", 9999),
    (0, "127.0.0.1:8881", None, None),               # switched off: a leftover
    (1, "corp:8080", None, None), (None, None, None, None), (1, 5, 7, None),
    (1, "127.0.0.1:x", "http://corp/p.pac", None),
])
def test_port_comes_from_the_proxy_settings(tool, enable, server, script, expected):
    assert tool.port_of(enable, server, script) == expected


def test_names_are_matched_whatever_their_case_and_suffix(tool):
    assert tool.wanted_names(["Discord", "UPDATE.EXE"]) == {"discord.exe", "update.exe"}


# ── Sampling ─────────────────────────────────────────────────────────────────
def test_each_connection_is_attributed_to_its_process(tool):
    result = run(tool, (DISCORD, [VIA_NET, AROUND, OTHERS]))
    assert [(r["pid"], r["role"], r["remote"], r["class"]) for r in result["connections"]] == [
        (MAIN, "main", "195.175.254.2:443", "DIRECT"),
        (NET, "NetworkService", "127.0.0.1:8881", "via SNIper")]
    assert [p["pid"] for p in result["processes"]] == [MAIN, NET]   # not the others
    assert tool.verdict(result) == ("1 connection went around SNIper, from Discord.exe "
                                    "[main]; 1 went through it.")


def test_it_samples_until_the_time_is_up_and_adds_up_what_it_saw(tool):
    later = (NET, "127.0.0.1", 8881, "TIME_WAIT", 50009)
    result = run(tool, ({}, []), (DISCORD, [VIA_NET]), (DISCORD, [VIA_NET, later]),
                 ({}, []), seconds=1)
    (row,) = result["connections"]
    assert (row["sockets"], row["states"]) == (2, ["ESTABLISHED", "TIME_WAIT"])
    assert (row["first"], row["last"]) == (0.1, 0.2)
    assert tool.verdict(result) == "Every connection to the internet went through SNIper (2)."


def test_listening_and_unconnected_sockets_count_for_nothing(tool):
    result = run(tool, (DISCORD, [(MAIN, "0.0.0.0", 0, "CLOSED", 50001)]))
    assert result["connections"] == []
    assert tool.verdict(result) == "No connection to the internet was seen."


def test_no_such_process(tool):
    result = run(tool, ({99: "other.exe"}, [OTHERS]))
    assert tool.verdict(result) == "No such process was running."
    assert "Processes\n  none" in tool.render(result)


@pytest.mark.parametrize("port, assumed", [(8881, False), (None, True)])
def test_an_assumed_port_is_said_to_be_one(tool, port, assumed):
    result = run(tool, (DISCORD, [VIA_NET]), port=port)
    assert (result["port"], result["port_assumed"]) == (8881, assumed)
    assert ("(assumed: " in tool.render(result)) is assumed
    assert result["connections"][0]["class"] == "via SNIper"


def test_render(tool):
    text = tool.render(run(tool, (DISCORD, [VIA_NET, AROUND, (
        MAIN, "2606:4700::1111", 443, "ESTABLISHED", 50005)]), seconds=0))
    assert text.startswith("App probe (read-only), one look\nSNIper's port: 8881\n")
    assert "NetworkService   via SNIper 127.0.0.1:8881" in text
    assert "DIRECT     195.175.254.2:443            SYN_SENT" in text
    assert "[2606:4700::1111]:443" in text
    assert text.endswith("2 connections went around SNIper, from Discord.exe [main]; "
                         "1 went through it.")


# ── As a program, on the real tables ─────────────────────────────────────────
@pytest.mark.skipif(not IS_WINDOWS, reason="Win32 process and connection lists")
def test_it_sees_this_process_and_its_connection(tool):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    accepted = []
    t = threading.Thread(target=lambda: accepted.append(listener.accept()), daemon=True)
    t.start()
    client = socket.create_connection(("127.0.0.1", port), timeout=10)
    t.join(10)
    try:
        # This process is a python.exe; pretend the listener is SNIper.
        result = tool.collect([os.path.basename(sys.executable)], port, 0)
        assert os.getpid() in [p["pid"] for p in result["processes"]]
        ours = [r for r in result["connections"] if r["pid"] == os.getpid()
                and r["remote"] == "127.0.0.1:%d" % port]
        assert len(ours) == 1
        assert ours[0]["class"] == "via SNIper" and "ESTABLISHED" in ours[0]["states"]
        assert ours[0]["role"] == "main"
    finally:
        client.close()
        for s, _ in accepted:
            s.close()
        listener.close()


@pytest.mark.slow
def test_as_a_program():
    proc = subprocess.run([sys.executable, _TOOL, "no-such-program-here", "--seconds", "0",
                           "--json"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    if not IS_WINDOWS:
        assert proc.stdout.strip() == "Windows only"
        return
    result = json.loads(proc.stdout)
    assert result["processes"] == [] and result["connections"] == []
    assert subprocess.run([sys.executable, _TOOL], capture_output=True,
                          timeout=60).returncode == 2   # a name is required


def test_source_never_writes():
    # The read-only promise, checked statically, as for proxy_state.py: no
    # registry write API, nothing that ends or changes a process or connection.
    with open(_TOOL, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    forbidden = {"SetValue", "SetValueEx", "DeleteValue", "DeleteKey", "CreateKey",
                 "CreateKeyEx", "KEY_WRITE", "KEY_ALL_ACCESS", "KEY_SET_VALUE",
                 "InternetSetOptionW", "TerminateProcess", "SetTcpEntry", "kill",
                 "OpenProcess", "WriteProcessMemory"}
    used = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    used |= {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert not used & forbidden
