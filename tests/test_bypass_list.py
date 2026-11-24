"""The bypass list of safe mode's manual proxy, as the parsers that decide for
real apps read it.

An app that reads only the manual proxy, not the PAC script, must go through
SNIper for every site, whether it ignores the bypass list or honors it, and
must reach local hosts directly if it honors it. v1.2.0 applied "*", which
told every app that honors the list to skip SNIper altogether: the Discord
app's updater did just that once it moved to reqwest 0.12 (issue #2).

Checked against what can be run here: Windows' own WinHTTP (with a proxy and
an origin server of the test's own; no setting is read and nothing leaves the
machine), the list matcher of Python's urllib, and ports of the matchers of
reqwest and requests, which a standard-library-only project can't import.
"""
from __future__ import annotations

import ctypes
import fnmatch
import ipaddress
import queue
import re
import socket
import threading
import urllib.request

import pytest

import sniper.winproxy as winproxy
from sniper.compat import IS_WINDOWS
from sniper.pac import bypass_rules
from test_pac import DIRECT, EXTRA_DIRECT, EXTRA_PROXIED, PROXIED, evaluate

LIST = ";".join(bypass_rules())
# The PAC script's own routing table. Parsers disagree on whether "<local>"
# covers an IPv6 literal (it has no dot), so nothing is said about those here;
# sniper.pac.bypass_rules explains why the list has no entry for them.
SITES = [h for h in PROXIED + EXTRA_PROXIED if ":" not in h]
LOCAL = [h for h in DIRECT + EXTRA_DIRECT if ":" not in h]
# What the Discord app and its updater ask for (the point of it all).
DISCORD = ["updates.discord.com", "discord.com", "gateway.discord.gg",
           "cdn.discordapp.com", "latency.discord.media"]


# ── The parsers ──────────────────────────────────────────────────────────────
def windows(override, host):
    """Windows' documented rules: patterns with "*" for any text, and
    "<local>" for names without a dot."""
    host = host.lower()
    return any("." not in host if entry == "<local>" else fnmatch.fnmatchcase(host, entry)
               for entry in override.lower().split(";"))


def urllib_(override, host):
    match = getattr(urllib.request, "_proxy_bypass_winreg_override", None)
    if match is None:
        pytest.skip("this Python has no separate bypass-list matcher")
    return bool(match(host, override))


def requests_(override, host):
    """A port of requests.utils.proxy_bypass_registry (requests 2.32). It
    matches patterns at the start of the name only."""
    for test in filter(None, override.split(";")):
        if test == "<local>" and "." not in host:
            return True
        test = test.replace(".", r"\.").replace("*", r".*").replace("?", r".")
        if re.match(test, host, re.I):
            return True
    return False


def reqwest(override, host):
    """A port of what reqwest 0.12.28 asks hyper-util 0.1.21, the versions in
    the Discord 1.0.61 updater: the list becomes a NO_PROXY list. A name
    matches its subdomains too, and "<local>" is just a name."""
    entries = []
    for entry in (e.strip() for e in override.split(";")):
        parts = entry.split(".")
        wild = parts.index("*") if "*" in parts else 0
        if 0 < wild <= 3 and set(parts[wild:]) == {"*"} and all(
                p.isdigit() for p in parts[:wild]):
            entry = ".".join(parts[:wild] + ["0"] * (4 - wild)) + "/%d" % (wild * 8)
        entries.append(entry.replace("*.", "").lower())
    host = host.lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return any(entry == "*" or host == entry or host.endswith("." + entry)
                   for entry in entries if entry)
    return any(address in ipaddress.ip_network(entry, strict=False)
               for entry in entries if re.match(r"[\d.]+(/\d+)?$", entry))


# Sites a parser sends direct all the same, and why that is fine. To Windows
# "10.*" is a pattern for names, so it also takes a site whose name starts with
# that label (the script wants a whole address). requests takes any name that
# starts like a local one. No real site is either.
NAME_PATTERN = {"10.example.com", "10.0.0.5.nip.io"}
QUIRKS = {
    windows: NAME_PATTERN, urllib_: NAME_PATTERN, reqwest: set(),
    requests_: NAME_PATTERN | {"x.localhost.com", "LOCALHOST.example.com",
                               "msftncsi.com.example.net", "printer.local.example.com"},
}
honoring = pytest.mark.parametrize("parser", list(QUIRKS),
                                   ids=lambda parser: parser.__name__.rstrip("_"))


# ── The regression, and the fix ──────────────────────────────────────────────
@honoring
def test_a_star_sends_every_site_past_sniper(parser):
    # What v1.2.0 applied, and why Discord stopped opening.
    assert all(parser("*", host) for host in DISCORD)


@honoring
@pytest.mark.parametrize("genuine", [None, "", "*", "<local>", "*.corp.example;<local>",
                                     "*;intranet.example", " * ; *.* ", "10.*;*"])
def test_every_site_goes_through_sniper(parser, genuine):
    applied = winproxy._bypass_list(genuine)
    assert [h for h in DISCORD if parser(applied, h)] == []
    assert {h for h in SITES if parser(applied, h)} == QUIRKS[parser]


@honoring
def test_local_hosts_stay_direct(parser):
    missed = [h for h in LOCAL if not parser(LIST, h)]
    # reqwest has no "<local>": a plain intranet name goes through SNIper.
    assert missed == (["intranet", "Intranet"] if parser is reqwest else [])


@pytest.mark.parametrize("engine", ["node", "jscript"])
def test_the_list_and_the_script_agree(engine, tmp_path):
    # Both are rendered from the same tables; this is the proof that they
    # still say the same thing once a real engine has evaluated the script.
    hosts = sorted(set(SITES + LOCAL + DISCORD))
    script = {h for h, answer in evaluate(engine, 8881, hosts, tmp_path).items()
              if answer == "DIRECT"}
    assert {h for h in hosts if windows(LIST, h)} - NAME_PATTERN == script


def test_the_users_own_entries_still_bypass():
    applied = winproxy._bypass_list("*.corp.example;intra.example")
    assert windows(applied, "wiki.corp.example") and reqwest(applied, "wiki.corp.example")
    assert windows(applied, "intra.example")


# ── Building it ──────────────────────────────────────────────────────────────
OWN = list(bypass_rules())


@pytest.mark.parametrize("genuine, expected", [
    (None, OWN),
    ("", OWN),
    (" ; ;", OWN),
    ("<local>", ["<local>"] + OWN[:-1]),                         # the user's come first
    ("*.corp;10.1.2.3", ["*.corp", "10.1.2.3"] + OWN),
    ("LOCALHOST;<LOCAL>", ["LOCALHOST", "<LOCAL>"] + OWN[1:-1]),  # whatever its case
    ("a.example;A.Example;a.example", ["a.example"] + OWN),
    ("a.example b.example\tc.example;;d.example",                 # Windows' separators
     ["a.example", "b.example", "c.example", "d.example"] + OWN),
    ("http://x.example:8080;<-loopback>", ["http://x.example:8080", "<-loopback>"] + OWN),
    ("*", OWN),
    ("*.*;.;**;a.example", ["a.example"] + OWN),
], ids=["absent", "empty", "blank", "local", "own-entries", "case", "repeated", "separators",
        "other-forms", "star", "only-wildcards"])
def test_the_list_is_the_users_entries_then_snipers_each_once(genuine, expected):
    assert winproxy._bypass_list(genuine) == ";".join(expected)


def test_leaving_out_a_star_is_noted_in_the_verbose_log_only():
    from sniper.logformat import friendly_format
    log = queue.Queue()
    winproxy._bypass_list("*.corp;*", log)
    (line,) = log.queue
    assert line == ("DEBUG", 'Your Windows proxy exceptions include "*" (every site); '
                             'SNIper leaves it out while it runs.')
    assert friendly_format(*line) is None
    winproxy._bypass_list("*.corp;<local>", log)   # nothing left out, nothing said
    assert log.qsize() == 1


# ── WinHTTP, for real ────────────────────────────────────────────────────────
class Listener:
    """A server on 127.0.0.1 that answers every request with an empty 200 and
    notes its request line."""

    def __init__(self):
        self.lines = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            with client:
                client.settimeout(10)
                try:
                    self.lines.append(client.recv(4096).split(b"\r\n")[0].decode("latin-1"))
                    client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                                   b"Connection: close\r\n\r\n")
                except OSError:
                    pass

    def close(self):
        self.sock.close()


@pytest.fixture
def proxy_and_origin():
    proxy, origin = Listener(), Listener()
    yield proxy, origin
    proxy.close()
    origin.close()


class WinHttp:
    """One WinHTTP session with a named proxy and a bypass list, as an app
    that read them from the registry would open it."""

    def __init__(self, proxy, bypass):
        self.dll = dll = ctypes.WinDLL("winhttp", use_last_error=True)
        handle, text, dword = ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong
        dll.WinHttpOpen.argtypes = [text, dword, text, text, dword]
        dll.WinHttpOpen.restype = handle
        dll.WinHttpConnect.argtypes = [handle, text, ctypes.c_ushort, dword]
        dll.WinHttpConnect.restype = handle
        dll.WinHttpOpenRequest.argtypes = [handle, text, text, text, text, handle, dword]
        dll.WinHttpOpenRequest.restype = handle
        dll.WinHttpSendRequest.argtypes = [handle, text, dword, handle, dword, dword,
                                           ctypes.c_size_t]
        dll.WinHttpReceiveResponse.argtypes = [handle, handle]
        dll.WinHttpSetTimeouts.argtypes = [handle] + [ctypes.c_int] * 4
        dll.WinHttpCloseHandle.argtypes = [handle]
        self.session = dll.WinHttpOpen("SNIper-pytest", 3, proxy, bypass, 0)
        self.error = 0 if self.session else ctypes.get_last_error()
        if self.session:
            dll.WinHttpSetTimeouts(self.session, 5000, 5000, 5000, 5000)

    def get(self, host, port):
        connect = self.dll.WinHttpConnect(self.session, host, port, 0)
        request = self.dll.WinHttpOpenRequest(connect, "GET", "/", None, None, None, 0)
        try:
            return bool(self.dll.WinHttpSendRequest(request, None, 0, None, 0, 0, 0)
                        and self.dll.WinHttpReceiveResponse(request, None))
        finally:
            self.dll.WinHttpCloseHandle(request)
            self.dll.WinHttpCloseHandle(connect)

    def close(self):
        if self.session:
            self.dll.WinHttpCloseHandle(self.session)


@pytest.mark.skipif(not IS_WINDOWS, reason="WinHTTP is Windows-only")
@pytest.mark.windows_integration
@pytest.mark.parametrize("genuine", [None, "<local>", "*.corp.example;10.1.2.3;*"])
def test_winhttp_takes_the_list_and_routes_by_it(proxy_and_origin, genuine):
    proxy, origin = proxy_and_origin
    http = WinHttp("127.0.0.1:%d" % proxy.port, winproxy._bypass_list(genuine))
    try:
        assert http.session, "WinHTTP refused the list: error %d" % http.error
        for site in ["updates.discord.com", "8.8.8.8", "172.32.0.1"]:
            assert http.get(site, 80)
            assert proxy.lines.pop() == "GET http://%s/ HTTP/1.1" % site
        for local in ["127.0.0.1", "localhost"]:
            assert http.get(local, origin.port)
            assert origin.lines.pop() == "GET / HTTP/1.1"   # straight to the origin
        assert proxy.lines == [] and origin.lines == []
    finally:
        http.close()


@pytest.mark.skipif(not IS_WINDOWS, reason="WinHTTP is Windows-only")
@pytest.mark.windows_integration
def test_one_bad_entry_would_lose_winhttp_the_whole_list():
    # Why the list has no entry for the IPv6 loopback address: an app that
    # hands it to WinHTTP could not open a session at all.
    http = WinHttp("127.0.0.1:1", LIST + ";::1")
    try:
        assert not http.session and http.error == 87   # ERROR_INVALID_PARAMETER
    finally:
        http.close()


def test_a_bracketed_ipv6_entry_would_send_real_sites_past_sniper():
    # requests reads "[::1]" as a set of characters a name may start with.
    assert requests_(LIST + ";[::1]", "1password.com")
    assert not requests_(LIST, "1password.com")
