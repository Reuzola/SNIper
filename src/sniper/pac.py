"""The proxy auto-config (PAC) script behind safe mode.

In safe mode the Windows proxy names a PAC script that SNIper serves itself,
and the script answers "PROXY 127.0.0.1:<port>; DIRECT". While SNIper runs,
traffic goes through it. Once SNIper is gone, nothing has to run for the
internet to keep working: a client that already loaded the script finds the
proxy refusing connections and falls back to the trailing DIRECT, and a client
that (re)fetches the script cannot download it and falls back to the manual
proxy safe mode sets next to it, whose bypass list ("*") sends every host
DIRECT (see sniper.winproxy).

Every session gets a new random script path, so each session's URL is unique:
clients notice the change at once, and the restore can tell exactly whether
the URL in the registry is still SNIper's own.

The script deliberately avoids dnsResolve, isInNet, myIpAddress, isResolvable
and dnsDomainLevels: DNS from inside a PAC goes to the system resolver, which
is the poisoned one SNIper exists to route around, and it is slow.
"""
from __future__ import annotations

import secrets

PAC_CONTENT_TYPE = "application/x-ns-proxy-autoconfig"

# Raw string, filled in with str.replace rather than % or format(), so the
# regex backslashes reach the JavaScript exactly as written. "PORT" occurs
# once. Rules, top to bottom:
# - plain intranet names, localhost, loopback and private IPv4 literals go
#   DIRECT, so routers and local services never depend on SNIper. The
#   indexOf test stands in for isPlainHostName on purpose:
#   isPlainHostName("2606:4700::1111") is true, and IPv6 literals must keep
#   going through SNIper;
# - Windows' connectivity check (NCSI) goes DIRECT, so the network icon never
#   shows "No internet" because of SNIper;
# - "; DIRECT" is always last: that is the fail-open.
_TEMPLATE = r"""function FindProxyForURL(url, host) {
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
  return "PROXY 127.0.0.1:PORT; DIRECT";
}
"""


def new_pac_path():
    """A fresh, unguessable script path for one session, like
    "/sniper-0123456789abcdef.pac". The .pac suffix matters: Windows only
    treats an http:// URL that looks like a script as one."""
    return "/sniper-" + secrets.token_hex(8) + ".pac"


def build_pac(port):
    """The PAC script for a SNIper listening on 127.0.0.1:port (ASCII text).

    Raises ValueError unless port is an int in 1..65535. A bool is refused
    too: Python counts True as 1, but True is no port.
    """
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an int in 1..65535, got %r" % (port,))
    return _TEMPLATE.replace("PORT", str(port))
