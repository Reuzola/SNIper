"""Tests for sniper.pac, the safe-mode PAC script.

The script text is pinned exactly, and then evaluated by a real JavaScript
engine against the routing table from the plan: node when it is on PATH, and
on Windows also the in-box JScript engine (cscript.exe), so the table runs on
a stock Windows machine too. Windows' own WinHTTP PAC engine evaluates it in
test_server_pac_windows.py.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

import pytest

from sniper.compat import IS_WINDOWS
from sniper.pac import PAC_CONTENT_TYPE, build_pac, new_pac_path

# The script exactly as the plan specifies it, port 8881.
EXPECTED_8881 = r"""function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if ((host.indexOf(".") < 0 && host.indexOf(":") < 0) ||
      host == "localhost" || dnsDomainIs(host, ".localhost") ||
      host == "127.0.0.1" || host == "::1" || host == "[::1]" ||
      /^(10|127)\.\d+\.\d+\.\d+$/.test(host) ||
      /^192\.168\.\d+\.\d+$/.test(host) ||
      /^169\.254\.\d+\.\d+$/.test(host) ||
      /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/.test(host) ||
      host == "msftconnecttest.com" || dnsDomainIs(host, ".msftconnecttest.com") ||
      host == "msftncsi.com" || dnsDomainIs(host, ".msftncsi.com"))
    return "DIRECT";
  return "PROXY 127.0.0.1:8881; DIRECT";
}
"""

# The plan's table: these go through SNIper...
PROXIED = ["discord.com", "www.example.com", "8.8.8.8", "2606:4700::1111",
           "notmsftconnecttest.com", "172.32.0.1", "10.example.com"]
# ...and these never depend on it.
DIRECT = ["WWW.MSFTCONNECTTEST.COM", "ipv6.msftconnecttest.com",
          "msftconnecttest.com", "dns.msftncsi.com", "localhost", "app.localhost",
          "127.0.0.1", "::1", "intranet", "192.168.1.1", "10.0.0.5",
          "172.16.0.1", "169.254.1.1"]
# Boundaries of the same rules, beyond the plan's table.
EXTRA_PROXIED = ["172.15.255.255", "192.169.0.1", "169.255.0.1", "11.0.0.1",
                 "10.0.0.5.nip.io", "x.localhost.com", "msftncsi.com.example.net",
                 "fe80::1", "LOCALHOST.example.com"]
EXTRA_DIRECT = ["[::1]", "LOCALHOST", "Intranet", "172.31.255.255",
                "127.1.2.3", "a.b.localhost", "www.msftncsi.com"]

_FORBIDDEN = ("dnsResolve", "isInNet", "myIpAddress", "isResolvable",
              "dnsDomainLevels", "isPlainHostName")


# ── The script text ──────────────────────────────────────────────────────────
def test_script_is_exactly_the_specified_one():
    assert build_pac(8881) == EXPECTED_8881


@pytest.mark.parametrize("port", [1, 80, 8881, 54321, 65535])
def test_port_substitution(port):
    script = build_pac(port)
    assert script == EXPECTED_8881.replace("8881", str(port))
    assert "PORT" not in script
    assert script.count("127.0.0.1:%d" % port) == 1


@pytest.mark.parametrize("port", [0, 65536, -1, 2 ** 32, "8881", 8881.0, None, True, False])
def test_invalid_port_raises_value_error(port):
    with pytest.raises(ValueError):
        build_pac(port)


def test_script_is_ascii_and_avoids_dns_functions():
    script = build_pac(8881)
    script.encode("ascii")  # raises if not
    for name in _FORBIDDEN:
        assert not re.search(r"\b%s\b" % name, script), name


def test_direct_fallback_is_the_last_return():
    returns = re.findall(r'return\s+"([^"]*)"\s*;', build_pac(4242))
    assert returns == ["DIRECT", "PROXY 127.0.0.1:4242; DIRECT"]
    assert returns[-1].endswith("; DIRECT")


def test_regex_backslashes_survive():
    # A format()/% template would have mangled these.
    assert r"/^(10|127)\.\d+\.\d+\.\d+$/" in build_pac(8881)


def test_new_pac_path_is_random_and_well_formed():
    paths = {new_pac_path() for _ in range(50)}
    assert len(paths) == 50
    for path in paths:
        assert re.match(r"^/sniper-[0-9a-f]{16}\.pac$", path), path


def test_content_type():
    assert PAC_CONTENT_TYPE == "application/x-ns-proxy-autoconfig"


# ── Evaluated by a real JavaScript engine ────────────────────────────────────
# ES3 only, so the in-box JScript engine runs it too. dnsDomainIs and
# shExpMatch are the standard PAC helpers; any other helper the script used
# would be undefined here and fail the run.
_HARNESS = r"""
function dnsDomainIs(host, domain) {
  return host.length >= domain.length &&
         host.substring(host.length - domain.length) == domain;
}
function shExpMatch(str, pattern) {
  var re = "";
  for (var i = 0; i < pattern.length; i++) {
    var c = pattern.charAt(i);
    if (c == "*") re += ".*";
    else if (c == "?") re += ".";
    else if ("\\^$.|+()[]{}/".indexOf(c) >= 0) re += "\\" + c;
    else re += c;
  }
  return new RegExp("^" + re + "$").test(str);
}
%(script)s
var hosts = [%(hosts)s];
var lines = [];
for (var i = 0; i < hosts.length; i++) {
  lines.push(hosts[i] + "\t" + FindProxyForURL("https://" + hosts[i] + "/", hosts[i]));
}
var text = lines.join("\n");
if (typeof WScript != "undefined") { WScript.Echo(text); } else { console.log(text); }
"""


def _engine_command(engine, path):
    if engine == "node":
        node = shutil.which("node")
        if node is None:
            pytest.skip("node is not on PATH")
        return [node, path]
    if not IS_WINDOWS:
        pytest.skip("cscript.exe (JScript) is Windows-only")
    cscript = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                           "System32", "cscript.exe")
    if not os.path.exists(cscript):
        pytest.skip("cscript.exe is not available")
    return [cscript, "//nologo", "//E:JScript", path]


def evaluate(engine, port, hosts, tmp_path):
    path = str(tmp_path / "pac_eval.js")
    with open(path, "w", encoding="ascii") as f:
        f.write(_HARNESS % {"script": build_pac(port),
                            "hosts": ", ".join(json.dumps(h) for h in hosts)})
    proc = subprocess.run(_engine_command(engine, path), capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    results = dict(line.split("\t", 1) for line in proc.stdout.strip().splitlines())
    assert sorted(results) == sorted(hosts), proc.stdout + proc.stderr
    return results


@pytest.mark.parametrize("engine", ["node", "jscript"])
def test_routing_table(engine, tmp_path):
    port = 8881
    hosts = PROXIED + DIRECT + EXTRA_PROXIED + EXTRA_DIRECT
    results = evaluate(engine, port, hosts, tmp_path)
    proxy = "PROXY 127.0.0.1:%d; DIRECT" % port
    wrong = {h: results[h] for h in PROXIED + EXTRA_PROXIED if results[h] != proxy}
    wrong.update({h: results[h] for h in DIRECT + EXTRA_DIRECT if results[h] != "DIRECT"})
    assert wrong == {}


@pytest.mark.parametrize("engine", ["node", "jscript"])
def test_routing_uses_the_substituted_port(engine, tmp_path):
    results = evaluate(engine, 54321, ["discord.com"], tmp_path)
    assert results == {"discord.com": "PROXY 127.0.0.1:54321; DIRECT"}
