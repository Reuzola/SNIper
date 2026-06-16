"""Tunables, DoH/plain-DNS server lists and the hop-by-hop header set.

Single source of truth: every other module imports these values from here
instead of redefining them. The values and their comments are unchanged from
the original embedded copy.
"""
from __future__ import annotations

BUFFER          = 32768
CONNECT_TIMEOUT = 10
DOH_TIMEOUT     = 4
UDP_DNS_TIMEOUT = 2.0
RESOLVE_BUDGET  = 3.0     # seconds — wall-clock cap for resolving ONE name
                          # (separate from CONNECT_TIMEOUT, which governs the
                          # TCP connect to the already-resolved IP)
DNS_CACHE_MAX   = 1024
MAX_CONNECTIONS = 256     # cap on concurrent handler threads (see accept loop)
# IP-based DoH servers — no domain resolution needed, immune to DNS poisoning.
#
# Order chosen for resilience on hostile networks: Cloudflare 1.1.1.1 is the
# fastest when reachable, but it is also the most commonly MITM'd and IP-
# blocked DoH endpoint (Turkey, Iran, etc. routinely intercept TLS to it),
# so Google and AdGuard follow immediately as alternates. DNS.SB is included
# because it is rarely on any block list. Quad9 (9.9.9.9) is intentionally
# omitted — it requires HTTP/2 (RFC 8484 §5.2), which Python's stdlib does
# not implement, so it always returns 505 over HTTP/1.1.
#
# The IPv6 endpoints come last: dual-stack and IPv4-only hosts try the
# faster IPv4 resolvers first, while on an IPv6-only network (NAT64/DNS64,
# DS-Lite) the IPv4 entries fail fast and the IPv6 ones take over.
DOH_SERVERS = [
    "https://1.1.1.1/dns-query",                 # Cloudflare primary
    "https://8.8.8.8/dns-query",                 # Google primary
    "https://94.140.14.14/dns-query",            # AdGuard primary
    "https://1.0.0.1/dns-query",                 # Cloudflare secondary
    "https://8.8.4.4/dns-query",                 # Google secondary
    "https://94.140.15.15/dns-query",            # AdGuard secondary
    "https://185.222.222.222/dns-query",         # DNS.SB — rarely blocked
    "https://[2606:4700:4700::1111]/dns-query",  # Cloudflare IPv6
    "https://[2001:4860:4860::8888]/dns-query",  # Google IPv6
    "https://[2a10:50c0::ad1:ff]/dns-query",     # AdGuard IPv6
]

# Plain UDP/TCP DNS resolvers — used when DoH endpoints are blocked at the
# network level (common with ISP-level DPI that interferes with TLS to
# well-known DoH IPs). Many ISPs only poison responses from their *own*
# resolver and pass UDP/53 traffic to other IPs through untouched.
#
# IPv6 resolvers come last for the IPv6-only-network case; on an IPv4 host
# they fail fast (no route) once the IPv4 entries above are exhausted.
PLAIN_DNS_SERVERS = [
    "1.1.1.1",                # Cloudflare
    "8.8.8.8",                # Google
    "9.9.9.9",                # Quad9
    "1.0.0.1",                # Cloudflare secondary
    "8.8.4.4",                # Google secondary
    "208.67.222.222",         # OpenDNS
    "94.140.14.14",           # AdGuard
    "185.222.222.222",        # DNS.SB
    "2606:4700:4700::1111",   # Cloudflare IPv6
    "2001:4860:4860::8888",   # Google IPv6
]

_HOP_BY_HOP = {
    b"connection", b"keep-alive", b"proxy-authenticate", b"proxy-authorization",
    b"proxy-connection", b"te", b"trailer", b"transfer-encoding", b"upgrade",
}

_DOH_FRAGMENT_SIZE = 2  # bytes per TCP segment for the DoH ClientHello
