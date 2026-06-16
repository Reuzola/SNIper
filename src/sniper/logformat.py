"""Friendly log formatter — translates raw proxy events into readable lines
for normal (non-verbose) mode. Verbose mode shows the original messages.
Moved verbatim from the embedded original; only the surrounding module changed.
"""
from __future__ import annotations

import re

_RX_STARTED = re.compile(
    r"^Proxy started on 127\.0\.0\.1:(?P<port>\d+)\s+\|\s+fragment=(?P<frag>\d+)B\s+\|\s+DoH=(?P<doh>on|off)$"
)
_RX_CONNECT = re.compile(r"^CONNECT\s+(?P<host>[^\s:]+):(?P<port>\d+)$")
_RX_FRAG    = re.compile(r"^\[frag\s+\d+B\]\s+(?P<host>[^\s:]+):(?P<port>\d+)$")
_RX_HTTP    = re.compile(r"^(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(?P<url>\S+)")
_RX_DOH_FAIL    = re.compile(r"^All DoH servers failed \((?P<host>[^)]+)\):.*->\s+trying public UDP DNS$")
_RX_UDP_OK      = re.compile(r"^Resolved (?P<host>\S+) via public UDP DNS -> (?P<ip>\S+)$")
_RX_TCP_OK      = re.compile(r"^Resolved (?P<host>\S+) via public TCP DNS -> (?P<ip>\S+)$")
_RX_V6_DOH_OK   = re.compile(r"^Resolved (?P<host>\S+) via DoH \(IPv6\) -> (?P<ip>\S+)$")
_RX_V6_UDP_OK   = re.compile(r"^Resolved (?P<host>\S+) via public UDP DNS \(IPv6\) -> (?P<ip>\S+)$")
_RX_V6_TCP_OK   = re.compile(r"^Resolved (?P<host>\S+) via public TCP DNS \(IPv6\) -> (?P<ip>\S+)$")
_RX_UDP_FAIL    = re.compile(r"^Public DNS unavailable for (?P<host>\S+)\s+->\s+system DNS$")
# Authoritative DNS negatives surface through the generic "Could not connect"
# error, so these two must be tried BEFORE _RX_NOCON (they share its prefix).
_RX_NOCON_NX     = re.compile(r"^Could not connect to (?P<host>[^:]+):(?P<port>\d+)\s+->\s+.*NXDOMAIN")
_RX_NOCON_NOADDR = re.compile(r"^Could not connect to (?P<host>[^:]+):(?P<port>\d+)\s+->\s+.*no usable address")
_RX_NOCON   = re.compile(r"^Could not connect to (?P<host>[^:]+):(?P<port>\d+)\s+->")
_RX_HTTPERR = re.compile(r"^HTTP relay error:")
_RX_BADPORT = re.compile(r"^Bad port in URL:")
_RX_ACCEPT  = re.compile(r"^Accept error")
_RX_STOPPED = re.compile(r"^Proxy stopped\.")


def friendly_format(level, msg):
    """
    Return (level, friendly_text) for normal-mode display, or None to suppress
    the line entirely. Verbose mode bypasses this and shows raw messages.
    """
    m = _RX_STARTED.match(msg)
    if m:
        doh = "secure DNS" if m["doh"] == "on" else "system DNS"
        return ("OK",
                f"Started — listening on port {m['port']}  ·  fragment {m['frag']}B  ·  {doh}")

    if _RX_STOPPED.match(msg):
        return ("OK", "Stopped — system proxy restored")

    m = _RX_CONNECT.match(msg)
    if m:
        host = m["host"]; port = m["port"]
        if port == "443":
            return ("CONN", f"→  {host}")
        return ("CONN", f"→  {host}:{port}")

    if _RX_FRAG.match(msg):
        # Internal confirmation that fragmentation fired — redundant after CONNECT.
        return None

    m = _RX_HTTP.match(msg)
    if m:
        url = m["url"]
        host = url
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/", 1)[0]
        return ("CONN", f"→  {host}  (HTTP)")

    m = _RX_DOH_FAIL.match(msg)
    if m:
        return ("WARNING", f"Secure DNS unavailable for {m['host']} — trying public DNS")

    m = _RX_UDP_OK.match(msg)
    if m:
        return ("OK", f"Resolved {m['host']} via public DNS  ({m['ip']})")

    m = _RX_TCP_OK.match(msg)
    if m:
        return ("OK", f"Resolved {m['host']} via TCP DNS  ({m['ip']})")

    m = _RX_V6_DOH_OK.match(msg)
    if m:
        return ("OK", f"Resolved {m['host']} via IPv6  ({m['ip']})")

    m = _RX_V6_UDP_OK.match(msg)
    if m:
        return ("OK", f"Resolved {m['host']} via IPv6 public DNS  ({m['ip']})")

    m = _RX_V6_TCP_OK.match(msg)
    if m:
        return ("OK", f"Resolved {m['host']} via IPv6 TCP DNS  ({m['ip']})")

    m = _RX_UDP_FAIL.match(msg)
    if m:
        return ("WARNING", f"Public DNS unreachable for {m['host']} — using system DNS")

    m = _RX_NOCON_NX.match(msg)
    if m:
        return ("WARNING", f"{m['host']} — host does not exist")

    m = _RX_NOCON_NOADDR.match(msg)
    if m:
        return ("WARNING", f"{m['host']} — no IPv4/IPv6 address")

    m = _RX_NOCON.match(msg)
    if m:
        return ("ERROR", f"Could not reach {m['host']}")

    if _RX_HTTPERR.match(msg):
        return ("ERROR", "HTTP relay failed")

    if _RX_BADPORT.match(msg):
        return ("ERROR", "Invalid port in request URL")

    if _RX_ACCEPT.match(msg):
        return ("ERROR", "Proxy stopped unexpectedly")

    # Pass-through for anything else, but keep the original level.
    if level == "DEBUG":
        return None
    return (level, msg)
