"""Windows integration tests for safe mode, on the real registry API.

- The whole Start -> apply -> serve -> Stop -> restore cycle in both modes,
  against the registry sandbox.
- A simulated hard kill (no restore runs) followed by launch recovery.
- Windows' own PAC engine (WinHTTP) evaluating the script SNIper serves, and
  failing to download it once SNIper is gone: the precondition for fail-open.

Nothing here touches the real proxy settings: winproxy is pointed at the
registry sandbox, and the WinHTTP queries name the script URL explicitly
instead of reading the user's configuration.
"""
from __future__ import annotations

import secrets
import urllib.request

import pytest

import sniper.server as server_mod
import sniper.winproxy as winproxy
from helpers import ABSENT, wait_until
from sniper.compat import IS_WINDOWS
from sniper.pac import build_pac
from sniper.server import ProxyServer
from test_pac import DIRECT, EXTRA_DIRECT, EXTRA_PROXIED, PROXIED

pytestmark = [pytest.mark.skipif(not IS_WINDOWS, reason="needs Windows"),
              pytest.mark.windows_integration]

if IS_WINDOWS:
    from helpers import (ERROR_WINHTTP_BAD_AUTO_PROXY_SCRIPT,
                         ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT,
                         winhttp_proxy_for_url)

CORP = (1, "corp:8080", "http://corp/p.pac")


@pytest.fixture
def server(registry_sandbox):
    s = ProxyServer()
    yield s
    s.stop()  # before the sandbox goes, whatever the test did


def fetch(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=10) as r:
        return r.read()


# ── Start / Stop in the sandbox ──────────────────────────────────────────────
@pytest.mark.parametrize("genuine", [(0, "", ABSENT), CORP], ids=["clean", "corp"])
def test_safe_mode_end_to_end(server, registry_sandbox, genuine):
    box = registry_sandbox
    box.set_live(*genuine)
    server.start(0, 2, False)
    url = server.pac_url
    # The script, and the manual proxy that bypasses every host.
    assert box.live_all() == (1, server.addr, url, "*")
    record = box.record()
    assert (record["AppliedMode"], record["AppliedAutoConfigURL"], record["Complete"]) \
        == ("pac", url, 1)
    # The URL in the registry is the one being served.
    assert fetch(box.live()[2]) == build_pac(server.port).encode("ascii")
    server.stop()
    assert box.live_all() == genuine + (ABSENT,)
    assert box.record() is None
    assert not box.exists(box.sniper_key)


@pytest.mark.parametrize("genuine", [(0, "", ABSENT), CORP], ids=["clean", "corp"])
def test_compat_mode_end_to_end(server, registry_sandbox, genuine):
    box = registry_sandbox
    box.set_live(*genuine)
    server.start(0, 2, False, compat=True)
    pac_while_running = "" if genuine[2] is not ABSENT else ABSENT
    assert box.live() == (1, server.addr, pac_while_running)
    assert box.record()["AppliedMode"] == "static"
    server.stop()
    assert box.live() == genuine
    assert box.record() is None


def test_switching_modes_between_sessions(server, registry_sandbox):
    box = registry_sandbox
    box.set_live(*CORP)
    server.start(0, 2, False, compat=True)
    server.stop()
    server.start(0, 2, False)
    assert box.live_all() == (1, server.addr, server.pac_url, "*")
    server.stop()
    assert box.live_all() == CORP + (ABSENT,)


@pytest.mark.parametrize("compat", [False, True], ids=["safe", "compat"])
def test_hard_kill_then_launch_recovery(registry_sandbox, monkeypatch, compat):
    box = registry_sandbox
    box.set_live(*CORP)
    # A hard kill runs no restore at all; stand in for that by disarming the
    # one the accept loop's fail-safe would do.
    disarmed = []
    monkeypatch.setattr(server_mod, "proxy_restore", lambda: disarmed.append(1))
    s = ProxyServer()
    s.start(0, 2, False, compat=compat)
    footprint = box.live()
    assert footprint != CORP
    s._sock.close()  # the port goes away, as with a dead process
    wait_until(s._unexpected_stop.is_set)
    assert disarmed == [1]
    del s  # and no stop()
    assert box.live() == footprint  # stranded
    assert winproxy.recover_orphaned_proxy() == "restored"
    assert box.live_all() == CORP + (ABSENT,)
    assert box.record() is None


# ── Windows' own PAC engine ──────────────────────────────────────────────────
def ask_windows(url, pac_url):
    """WinHttpGetProxyForUrl as most apps run it (out of process, in WinHTTP's
    autoproxy service); in process only if the service itself failed."""
    result = winhttp_proxy_for_url(url, pac_url)
    if not result.ok and result.error not in (ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT,
                                              ERROR_WINHTTP_BAD_AUTO_PROXY_SCRIPT):
        print("out of process failed (%r); retrying in process" % (result,))
        result = winhttp_proxy_for_url(url, pac_url, in_process=True)
    print("%s -> %r" % (url, result))  # raw results, shown on failure or with -s
    return result


# WinHTTP answers DIRECT for loopback and link-local addresses before it runs
# any script: even a script that proxies everything gets DIRECT for these
# (checked by hand on Windows 11 26200, in and out of process). For them the
# script's own answer is not observable here; test_pac.py's JavaScript
# engines check it.
WINHTTP_OWN_BYPASS = {"fe80::1"}


def url_for(host):
    return "https://%s/" % ("[%s]" % host if ":" in host and not host.startswith("[")
                            else host)


@pytest.mark.slow
def test_windows_pac_engine_evaluates_the_served_script(server, registry_sandbox):
    server.start(0, 2, False)
    port, pac_url = server.port, server.pac_url
    me = "127.0.0.1:%d" % port

    # The plan's three probes, then the whole routing table.
    assert ask_windows("https://example.com/", pac_url).names_proxy(me)
    assert ask_windows("http://www.msftconnecttest.com/connecttest.txt", pac_url).direct
    assert ask_windows("http://192.168.1.1/", pac_url).direct
    wrong = {}
    for host in PROXIED + EXTRA_PROXIED:
        if host in WINHTTP_OWN_BYPASS:
            continue
        result = ask_windows(url_for(host), pac_url)
        if not result.names_proxy(me):
            wrong[host] = result
    for host in DIRECT + EXTRA_DIRECT + sorted(WINHTTP_OWN_BYPASS):
        result = ask_windows(url_for(host), pac_url)
        if not result.direct:
            wrong[host] = result
    assert wrong == {}

    # SNIper gone: a client that (re)fetches the script cannot download it,
    # which for a non-mandatory PAC means DIRECT. A path never asked for
    # before, so no cached copy of the script can answer instead.
    server.stop()
    gone = "http://127.0.0.1:%d/sniper-%s.pac" % (port, secrets.token_hex(8))
    result = ask_windows("https://example.com/", gone)
    assert not result.ok
    assert result.error == ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT
