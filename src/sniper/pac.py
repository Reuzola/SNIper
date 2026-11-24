"""The proxy auto-config (PAC) script behind safe mode, and the rules for what
never goes through SNIper.

In safe mode the Windows proxy names a PAC script that SNIper serves itself,
and the script answers "PROXY 127.0.0.1:<port>; DIRECT". While SNIper runs,
traffic goes through it. Once SNIper is gone, a client that already loaded the
script needs nothing to run for its internet to keep working: it finds the
proxy refusing connections and falls back to the trailing DIRECT. A client
that (re)fetches the script cannot download it and falls back to the manual
proxy safe mode sets next to it, which names SNIper too, so it waits for the
restore (see sniper.winproxy).

Every session gets a new random script path, so each session's URL is unique:
clients notice the change at once, and the restore can tell exactly whether
the URL in the registry is still SNIper's own.

The script deliberately avoids dnsResolve, isInNet, myIpAddress, isResolvable
and dnsDomainLevels: DNS from inside a PAC goes to the system resolver, which
is the poisoned one SNIper exists to route around, and it is slow.

What never goes through SNIper is defined once, in the _DIRECT_* tables. The
script's conditions and the manual proxy's bypass list are both rendered from
them, so apps that follow the script and apps that read only the manual proxy
always agree on it.
"""
from __future__ import annotations

import secrets

PAC_CONTENT_TYPE = "application/x-ns-proxy-autoconfig"

# ── What never goes through SNIper ────────────────────────────────────────────
# - local hosts: plain intranet names, localhost, .local (mDNS and Active
#   Directory names, which public DNS does not know), and loopback,
#   link-local and private IPv4 addresses, so routers and local services
#   never depend on SNIper;
# - Windows' connectivity check (NCSI), so the network icon never shows "No
#   internet" because of SNIper.
_DIRECT_DOMAINS  = ("localhost", "msftconnecttest.com", "msftncsi.com")  # and below
_DIRECT_SUFFIXES = ("local",)                                            # only below
_DIRECT_IPV4     = (("127", "10", "192.168", "169.254")
                    + tuple("172.%d" % n for n in range(16, 32)))        # prefixes


def bypass_rules():
    """The rules as entries of a Windows proxy bypass list, in the order
    Windows itself would write them ("<local>" last).

    Only forms that mean the same thing to every parser that could be checked
    are used (WinHTTP, WinINet, Chromium, .NET Framework, hyper-util, Python's
    urllib and requests). The IPv6 loopback address is left out on purpose:
    unbracketed, it makes WinHTTP and WinINet refuse the whole list, and in
    brackets requests reads it as a regular expression that matches every
    host starting with "1". "<local>" covers it in most of them anyway, and
    SNIper proxies it for the rest."""
    rules = []
    for domain in _DIRECT_DOMAINS:
        rules += [domain, "*." + domain]
    rules += ["*." + suffix for suffix in _DIRECT_SUFFIXES]
    rules += [prefix + ".*" for prefix in _DIRECT_IPV4]
    return tuple(rules) + ("<local>",)


def _script_conditions():
    """The same rules as the script's JavaScript conditions, one per line."""
    # The indexOf test stands in for isPlainHostName on purpose:
    # isPlainHostName("2606:4700::1111") is true, and IPv6 literals must keep
    # going through SNIper.
    lines = ['(host.indexOf(".") < 0 && host.indexOf(":") < 0)',
             'host == "::1" || host == "[::1]"']
    lines += ['host == "%s" || dnsDomainIs(host, ".%s")' % (domain, domain)
              for domain in _DIRECT_DOMAINS]
    lines += ['dnsDomainIs(host, ".%s")' % suffix for suffix in _DIRECT_SUFFIXES]
    # Only a full dotted quad is an address: 10.example.com is a site.
    lines.append(r"(/^\d+\.\d+\.\d+\.\d+$/.test(host) &&" "\n"
                 r"       /^(%s)\./.test(host))"
                 % "|".join(prefix.replace(".", r"\.") for prefix in _DIRECT_IPV4))
    return " ||\n      ".join(lines)


# Filled in with str.replace: "PORT" occurs once. "; DIRECT" is always last.
_TEMPLATE = """function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (%s)
    return "DIRECT";
  return "PROXY 127.0.0.1:PORT; DIRECT";
}
""" % _script_conditions()


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
