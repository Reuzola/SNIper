"""Name resolution chain: DoH over a fragmented ClientHello, then plain
UDP/53 and TCP/53 public resolvers, then the system resolver as a last
resort. Also holds the DNS packet builder/parser, the positive/negative
caches and the address-family routing probe.

Logic is unchanged from the original embedded proxy core; only the shared
constants now come from sniper.config.
"""
from __future__ import annotations

import socket
import base64
import ssl
import time
import threading
import struct
import random
from collections import OrderedDict

from sniper.config import (
    DOH_SERVERS,
    PLAIN_DNS_SERVERS,
    DOH_TIMEOUT,
    UDP_DNS_TIMEOUT,
    RESOLVE_BUDGET,
    DNS_CACHE_MAX,
    _DOH_FRAGMENT_SIZE,
)


def _is_ip(h):
    """True if h is a literal IPv4 or IPv6 address (so no DNS is needed)."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, h)
            return True
        except (OSError, ValueError):
            pass
    return False

_doh_ssl_ctx = ssl.create_default_context()
try:
    _doh_ssl_ctx.set_alpn_protocols(["http/1.1"])
except (NotImplementedError, AttributeError):
    pass
# Pin the TLS floor explicitly. create_default_context() already defaults to
# 1.2, but stating it removes the version-dependent ambiguity across Python
# builds. The floor stays at 1.2 (not 1.3) so the handshake still completes
# through TLS-MITM appliances that lack 1.3 support; 1.3 is still offered and
# used whenever the path allows it.
_doh_ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

_dns_cache: "OrderedDict[str, tuple[str, float]]" = OrderedDict()
_dns_lock = threading.Lock()


def _cache_get(hostname):
    with _dns_lock:
        entry = _dns_cache.get(hostname)
        if entry is None:
            return None
        ip, expires = entry
        if time.time() >= expires:
            _dns_cache.pop(hostname, None)
            return None
        _dns_cache.move_to_end(hostname)
        return ip


def _cache_put(hostname, ip, ttl):
    with _dns_lock:
        _dns_cache[hostname] = (ip, time.time() + ttl)
        _dns_cache.move_to_end(hostname)
        while len(_dns_cache) > DNS_CACHE_MAX:
            _dns_cache.popitem(last=False)


# Negative cache — remembers authoritative "does not exist" (NXDOMAIN) and
# "no usable address" (NODATA for both families) answers so repeated requests
# for the same dead host fail instantly instead of re-running the chain.
# Bounded like the positive cache; shares its lock.
_dns_neg_cache: "OrderedDict[str, tuple[float, str]]" = OrderedDict()


def _neg_cache_get(hostname):
    """Return the cached negative reason ('nxdomain' / 'noaddr') or None."""
    with _dns_lock:
        entry = _dns_neg_cache.get(hostname)
        if entry is None:
            return None
        expires, reason = entry
        if time.time() >= expires:
            _dns_neg_cache.pop(hostname, None)
            return None
        _dns_neg_cache.move_to_end(hostname)
        return reason


def _neg_cache_put(hostname, reason, ttl):
    with _dns_lock:
        _dns_neg_cache[hostname] = (time.time() + ttl, reason)
        _dns_neg_cache.move_to_end(hostname)
        while len(_dns_neg_cache) > DNS_CACHE_MAX:
            _dns_neg_cache.popitem(last=False)


def _negative_error(hostname, reason):
    """gaierror for an authoritative negative answer ('nxdomain' / 'noaddr')."""
    if reason == "nxdomain":
        msg = f"{hostname} does not exist (NXDOMAIN)"
    else:
        msg = f"{hostname} has no usable address (no A or AAAA record)"
    return socket.gaierror(getattr(socket, "EAI_NONAME", -2), msg)


# ── Address-family routing probe ──────────────────────────────────────────────
# Reachability of each address family, probed via a connected UDP socket.
# connect() on a datagram socket sends no packets — it only asks the kernel to
# pick a route and a source address — so the probe is free and silent. On an
# IPv4-only host this lets the resolver skip the IPv6 DoH/DNS endpoints
# instead of collecting a WSAENETUNREACH from each of them on every pass.
# Cached and re-probed on a coarse timer so a host that gains or loses a
# family is noticed without paying the syscall on every lookup.
_FAMILY_PROBE_ADDR = {
    socket.AF_INET:  "1.1.1.1",
    socket.AF_INET6: "2606:4700:4700::1111",
}
_FAMILY_RECHECK = 30.0  # seconds between route re-probes
_family_state: dict = {}
_family_lock = threading.Lock()


def _family_usable(family):
    """True if the host currently has a usable route for this address family."""
    now = time.monotonic()
    with _family_lock:
        cached = _family_state.get(family)
        if cached is not None and now < cached[1]:
            return cached[0]
    usable = False
    try:
        s = socket.socket(family, socket.SOCK_DGRAM)
        try:
            s.connect((_FAMILY_PROBE_ADDR[family], 53))
            src = s.getsockname()[0]
            # A link-local or loopback source address means an interface
            # exists but there is no usable global route.
            usable = not (src.startswith("fe80") or src in ("::", "::1", "0.0.0.0", "127.0.0.1"))
        finally:
            s.close()
    except OSError:
        usable = False
    with _family_lock:
        _family_state[family] = (usable, now + _FAMILY_RECHECK)
    return usable


def _skip_unroutable(server_ip):
    """True if this resolver's address family has no route while the other one
    does — skipping it avoids a guaranteed network-unreachable error. When
    NEITHER family probes usable the filter disengages (fail open), so the
    resolver still tries everything rather than nothing."""
    if ":" in server_ip:
        fam, other = socket.AF_INET6, socket.AF_INET
    else:
        fam, other = socket.AF_INET, socket.AF_INET6
    return not _family_usable(fam) and _family_usable(other)


# ── Plain UDP DNS (RFC 1035) — fallback when DoH endpoints are blocked ──────
_DNS_TYPE_A    = 1
_DNS_TYPE_AAAA = 28
_DNS_TYPE_SOA  = 6

# DNS lookup outcome classes. The parser distinguishes an authoritative
# negative ("this name does not exist") from a transport-level failure
# ("we never got a trustworthy answer") so the resolver chain can stop
# immediately on the former instead of marching through every fallback.
_DNS_OK             = 0   # positive answer — payload is (ip, ttl)
_DNS_NXDOMAIN       = 1   # RCODE 3: the name does not exist (all record types)
_DNS_NODATA         = 2   # RCODE 0, no answer of the queried type
_DNS_TRANSPORT_FAIL = 3   # SERVFAIL / malformed / timeout / no usable reply

# Negative answers are cached with the SOA minimum TTL when the authority
# section provides one (RFC 2308), clamped to these bounds; without a SOA a
# short default keeps dead hosts from being re-queried in a tight loop.
_NEG_TTL_DEFAULT = 30
_NEG_TTL_MIN     = 15
_NEG_TTL_MAX     = 600

_MIN_ATTEMPT_SECS = 0.2   # skip a server when less budget than this remains


def _build_dns_query(hostname, tid, qtype=_DNS_TYPE_A):
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in hostname.encode("ascii").split(b"."):
        if not part:
            continue
        if len(part) > 63:
            raise ValueError("DNS label too long")
        qname += bytes([len(part)]) + part
    qname += b"\x00"
    return header + qname + struct.pack(">HH", qtype, 1)


def _skip_name(buf, off):
    while off < len(buf):
        l = buf[off]
        if l == 0:
            return off + 1
        if l & 0xC0 == 0xC0:
            return off + 2
        off += 1 + l
    return off


def _negative_ttl(buf, off, nscount):
    """Negative-cache TTL from the authority section's SOA record (RFC 2308).

    `off` points at the first authority record. Returns min(SOA record TTL,
    SOA MINIMUM field) clamped to [_NEG_TTL_MIN, _NEG_TTL_MAX], or
    _NEG_TTL_DEFAULT when there is no parseable SOA.
    """
    for _ in range(nscount):
        if off >= len(buf):
            break
        off = _skip_name(buf, off)
        if off + 10 > len(buf):
            break
        rtype, _rclass, ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        if off + rdlen > len(buf):
            break
        # SOA rdata = MNAME + RNAME (variable-length names) + 5×uint32;
        # MINIMUM is the last of the five, i.e. the final 4 bytes of the
        # rdata. 22 = two 1-byte root names + the 20 fixed bytes.
        if rtype == _DNS_TYPE_SOA and rdlen >= 22:
            minimum = struct.unpack(">I", buf[off + rdlen - 4:off + rdlen])[0]
            return max(_NEG_TTL_MIN, min(int(min(ttl, minimum)), _NEG_TTL_MAX))
        off += rdlen
    return _NEG_TTL_DEFAULT


def _parse_dns_response(buf, expected_tid, want_type=_DNS_TYPE_A):
    """Classify a DNS response. Returns an (outcome, data) tuple:

      (_DNS_OK, (ip, ttl))          — first record of want_type found
      (_DNS_NXDOMAIN, neg_ttl)      — RCODE 3: the name does not exist
      (_DNS_NODATA, neg_ttl)        — name exists, no record of want_type
      (_DNS_TRANSPORT_FAIL, None)   — malformed / mismatched / server failure

    NXDOMAIN and NODATA are *authoritative* negatives — whether they may be
    trusted is the caller's decision (DoH yes, plain UDP/TCP no). Never
    raises on malformed or truncated input.
    """
    fail = (_DNS_TRANSPORT_FAIL, None)
    if len(buf) < 12:
        return fail
    tid, flags, qd, an, ns, _ar = struct.unpack(">HHHHHH", buf[:12])
    if tid != expected_tid:
        return fail
    rcode = flags & 0x000F
    if rcode == 3:
        nxdomain = True
    elif rcode == 0:
        nxdomain = False
    else:
        return fail                  # SERVFAIL, REFUSED, ... — not an answer
    off = 12
    for _ in range(qd):
        off = _skip_name(buf, off)
        off += 4
    # Walk answers — skip CNAMEs and unrelated types, return first match.
    # (Walked even for NXDOMAIN, which may carry CNAME answers, so that
    # `off` lands on the authority section for the SOA scan below.)
    for _ in range(an):
        if off >= len(buf):
            return fail
        off = _skip_name(buf, off)
        if off + 10 > len(buf):
            return fail
        rtype, _rclass, ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        if off + rdlen > len(buf):
            return fail
        if not nxdomain and rtype == want_type:
            if want_type == _DNS_TYPE_A and rdlen == 4:
                return _DNS_OK, (".".join(str(b) for b in buf[off:off + 4]), int(ttl))
            if want_type == _DNS_TYPE_AAAA and rdlen == 16:
                return _DNS_OK, (socket.inet_ntop(socket.AF_INET6, buf[off:off + 16]), int(ttl))
        off += rdlen
    if nxdomain:
        return _DNS_NXDOMAIN, _negative_ttl(buf, off, ns)
    if flags & 0x0200:               # TC: answers truncated — not trustworthy
        return fail
    return _DNS_NODATA, _negative_ttl(buf, off, ns)


def _udp_dns_query(hostname, server_ip, qtype=_DNS_TYPE_A, timeout=UDP_DNS_TIMEOUT):
    """Send one A/AAAA query over UDP/53; returns a _parse_dns_response tuple."""
    tid = random.randint(0, 0xFFFF)
    pkt = _build_dns_query(hostname, tid, qtype)
    family = socket.AF_INET6 if ":" in server_ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(pkt, (server_ip, 53))
        resp, _addr = s.recvfrom(2048)
    except OSError:
        return _DNS_TRANSPORT_FAIL, None
    finally:
        try: s.close()
        except OSError: pass
    return _parse_dns_response(resp, tid, qtype)


def _resolve_via_public_udp(hostname, log_q, qtype=_DNS_TYPE_A, deadline=None):
    """Try plain UDP DNS against public resolvers. Returns (ip, ttl) or None.

    Trust boundary: answers on UDP/53 are unauthenticated, so a negative
    (NXDOMAIN/NODATA) here may be a spoofed injection from a hostile network
    and must NOT end the resolution chain — it is treated like any other
    failure and the next server is tried.
    """
    for srv in PLAIN_DNS_SERVERS:
        if _skip_unroutable(srv):
            continue
        timeout = UDP_DNS_TIMEOUT
        if deadline is not None:
            timeout = min(timeout, deadline - time.monotonic())
            if timeout < _MIN_ATTEMPT_SECS:
                break
        outcome, data = _udp_dns_query(hostname, srv, qtype=qtype, timeout=timeout)
        if outcome == _DNS_OK:
            ip, ttl = data
            log_q.put(("DEBUG", f"UDP-DNS  {hostname} -> {ip}  [{srv}]"))
            return ip, max(int(ttl), 30)
        elif outcome in (_DNS_NXDOMAIN, _DNS_NODATA):
            log_q.put(("DEBUG", f"UDP-DNS  {srv}: unauthenticated negative for {hostname} — ignored"))
        else:
            log_q.put(("DEBUG", f"UDP-DNS  {srv} failed for {hostname}"))
    return None


# ── Plain TCP DNS (RFC 7766) — fallback when UDP/53 is intercepted ───────────
# Some ISPs rewrite responses on UDP/53 to public resolvers but pass TCP/53
# through untouched. Wire format: 2-byte big-endian length prefix + DNS msg.


def _tcp_dns_query(hostname, server_ip, qtype=_DNS_TYPE_A, timeout=UDP_DNS_TIMEOUT):
    """Send one A/AAAA query over TCP/53; returns a _parse_dns_response tuple."""
    tid = random.randint(0, 0xFFFF)
    pkt = _build_dns_query(hostname, tid, qtype)
    framed = struct.pack(">H", len(pkt)) + pkt

    family = socket.AF_INET6 if ":" in server_ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect((server_ip, 53))
        s.sendall(framed)
        head = b""
        while len(head) < 2:
            chunk = s.recv(2 - len(head))
            if not chunk:
                return _DNS_TRANSPORT_FAIL, None
            head += chunk
        resp_len = struct.unpack(">H", head)[0]
        body = b""
        while len(body) < resp_len:
            chunk = s.recv(resp_len - len(body))
            if not chunk:
                return _DNS_TRANSPORT_FAIL, None
            body += chunk
    except OSError:
        return _DNS_TRANSPORT_FAIL, None
    finally:
        try: s.close()
        except OSError: pass
    return _parse_dns_response(body, tid, qtype)


def _resolve_via_public_tcp(hostname, log_q, qtype=_DNS_TYPE_A, deadline=None):
    """Try plain TCP DNS against public resolvers. Returns (ip, ttl) or None.

    Trust boundary: same as the UDP pass — an unauthenticated negative must
    NOT end the chain, so it is treated as a failure and the next server is
    tried.
    """
    for srv in PLAIN_DNS_SERVERS:
        if _skip_unroutable(srv):
            continue
        timeout = UDP_DNS_TIMEOUT
        if deadline is not None:
            timeout = min(timeout, deadline - time.monotonic())
            if timeout < _MIN_ATTEMPT_SECS:
                break
        outcome, data = _tcp_dns_query(hostname, srv, qtype=qtype, timeout=timeout)
        if outcome == _DNS_OK:
            ip, ttl = data
            log_q.put(("DEBUG", f"TCP-DNS  {hostname} -> {ip}  [{srv}]"))
            return ip, max(int(ttl), 30)
        elif outcome in (_DNS_NXDOMAIN, _DNS_NODATA):
            log_q.put(("DEBUG", f"TCP-DNS  {srv}: unauthenticated negative for {hostname} — ignored"))
        else:
            log_q.put(("DEBUG", f"TCP-DNS  {srv} failed for {hostname}"))
    return None


# ── Fragmented HTTPS GET (for DoH) ────────────────────────────────────────────
# Python's `urllib` (and `ssl.wrap_socket` in general) writes the TLS
# ClientHello in a single TCP segment. On networks that block DoH via DPI —
# either by fingerprinting the ClientHello or by RST-injecting traffic to
# well-known resolver IPs — every DoH request fails before DNS is resolved at
# all, so the proxy falls back to plain UDP DNS, which is itself often
# poisoned for blocked hostnames.
#
# We drive the TLS handshake by hand through SSL BIOs and send the first
# outgoing TCP write (the ClientHello, with its TLS fingerprint and extensions)
# split into 2-byte segments — the same trick the proxy uses for client
# traffic. Once the handshake completes, the rest of the connection runs at
# normal speed.


def _send_segmented(sock, data, seg_size):
    """Send `data` in seg_size-byte TCP segments. TCP_NODELAY must be on."""
    if seg_size < 1:
        seg_size = 1
    off, n = 0, len(data)
    while off < n:
        end = min(off + seg_size, n)
        chunk_off = off
        while chunk_off < end:
            sent = sock.send(data[chunk_off:end])
            if sent == 0:
                raise OSError("socket closed during segmented send")
            chunk_off += sent
        off = end


def _parse_http_response(raw):
    """Minimal HTTP/1.x response parser. Handles chunked transfer encoding."""
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        raise ValueError("malformed HTTP response (no header terminator)")
    header_block = raw[:sep].decode("latin-1", errors="replace")
    body = raw[sep + 4:]

    status_line, _, rest = header_block.partition("\r\n")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise ValueError("malformed HTTP status line")
    status = int(parts[1])

    headers = {}
    for line in rest.split("\r\n"):
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()

    if headers.get("transfer-encoding", "").lower() == "chunked":
        decoded = bytearray()
        i = 0
        while i < len(body):
            j = body.find(b"\r\n", i)
            if j < 0:
                break
            size_str = body[i:j].split(b";", 1)[0].strip()
            try:
                size = int(size_str, 16)
            except ValueError:
                break
            if size == 0:
                break
            start = j + 2
            decoded.extend(body[start:start + size])
            i = start + size + 2
        body = bytes(decoded)
    return status, body


def _fragmented_https_get(server_ip, path_with_query, headers, timeout):
    """Issue HTTPS GET to server_ip:443 with the ClientHello fragmented.

    Returns (status, body). Raises on connect / handshake / read errors.
    """
    sock = socket.create_connection((server_ip, 443), timeout=timeout)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        ssl_obj = _doh_ssl_ctx.wrap_bio(
            incoming, outgoing, server_hostname=server_ip,
        )
        client_hello_sent = False

        def _flush():
            nonlocal client_hello_sent
            pending = outgoing.read()
            if not pending:
                return
            if not client_hello_sent:
                _send_segmented(sock, pending, _DOH_FRAGMENT_SIZE)
                client_hello_sent = True
            else:
                sock.sendall(pending)

        def _pull():
            sock.settimeout(timeout)
            chunk = sock.recv(16384)
            if not chunk:
                raise OSError("EOF during TLS exchange")
            incoming.write(chunk)

        while True:
            try:
                ssl_obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                _flush()
                _pull()
            except ssl.SSLWantWriteError:
                _flush()
        _flush()

        # An IPv6 literal must be bracketed in the Host header (RFC 7230
        # §5.4); create_connection() above takes the bare form.
        host_header = f"[{server_ip}]" if ":" in server_ip else server_ip
        lines = [
            f"GET {path_with_query} HTTP/1.1",
            f"Host: {host_header}",
            "Connection: close",
        ]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        req = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")

        sent = 0
        while sent < len(req):
            try:
                n = ssl_obj.write(req[sent:])
                sent += n
                _flush()
            except ssl.SSLWantReadError:
                _flush()
                _pull()
            except ssl.SSLWantWriteError:
                _flush()

        response = bytearray()
        while True:
            try:
                data = ssl_obj.read(16384)
                if not data:
                    break
                response.extend(data)
            except ssl.SSLWantReadError:
                _flush()
                try:
                    _pull()
                except OSError:
                    break
            except ssl.SSLZeroReturnError:
                break
            except ssl.SSLError as e:
                if "UNEXPECTED_EOF" in str(e).upper():
                    break
                raise

        return _parse_http_response(bytes(response))
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _doh_lookup(hostname, qtype_name, qtype_num, log_q, deadline=None):
    """One DoH pass over the configured servers. Returns (outcome, data).

    Stops at the FIRST authoritative answer — positive, NXDOMAIN or NODATA —
    because DoH runs over verified TLS to a known resolver IP, so a clean
    answer can be trusted (a MITM fails certificate verification, which is
    counted separately below). Servers that transport-fail are skipped; only
    when no server produced a trustworthy reply does the whole pass report
    _DNS_TRANSPORT_FAIL, and only then may the caller fall back to
    unauthenticated UDP/TCP.

    Uses RFC 8484 wire format (Content-Type: application/dns-message) — the
    standard binary DoH protocol every compliant resolver implements
    identically. JSON DoH (`application/dns-json`) is not universally
    supported: Google rejects it at `/dns-query`, Quad9 only accepts RFC 8484
    over HTTP/2, others return 400/505 inconsistently. Binary wire format
    avoids the mismatch entirely and reuses the same parser the UDP path uses.
    The TLS ClientHello is fragmented so DPI engines that fingerprint or
    RST-inject DoH connections cannot block the lookup.
    """
    last_err = None
    cert_failures = 0
    for srv in DOH_SERVERS:
        try:
            # IPv6 endpoints wrap the address in brackets, e.g.
            # "https://[2606:4700:4700::1111]/dns-query". The brackets are URL
            # syntax only — socket.create_connection() needs the bare address,
            # so strip them here (a bracketed literal is not a valid host).
            after = srv[len("https://"):]
            slash = after.find("/")
            authority = after[:slash] if slash > 0 else after
            path = after[slash:] if slash > 0 else "/"
            if authority.startswith("[") and "]" in authority:
                server_ip = authority[1:authority.index("]")]
            else:
                server_ip = authority

            if _skip_unroutable(server_ip):
                continue
            timeout = DOH_TIMEOUT
            if deadline is not None:
                timeout = min(timeout, deadline - time.monotonic())
                if timeout < _MIN_ATTEMPT_SECS:
                    break

            # RFC 8484 §4.1: id SHOULD be 0 for HTTP cache friendliness.
            tid = 0
            pkt = _build_dns_query(hostname, tid, qtype_num)
            b64 = base64.urlsafe_b64encode(pkt).rstrip(b"=").decode("ascii")
            status, body = _fragmented_https_get(
                server_ip, f"{path}?dns={b64}",
                headers={
                    "Accept":     "application/dns-message",
                    "User-Agent": "Mozilla/5.0 SNIper/1.1.5",
                },
                timeout=timeout,
            )
            if status != 200 or len(body) < 12:
                log_q.put(("DEBUG",
                           f"DoH  {srv} returned HTTP {status} for {hostname}"))
                continue
            outcome, data = _parse_dns_response(body, tid, qtype_num)
            if outcome == _DNS_OK:
                ip, ttl = data
                log_q.put(("DEBUG",
                           f"DoH  {hostname} {qtype_name} -> {ip}  [{srv}]"))
                return _DNS_OK, (ip, max(int(ttl), 30))
            if outcome == _DNS_NXDOMAIN or outcome == _DNS_NODATA:
                # Authoritative negative over authenticated TLS — trustworthy,
                # so it ends the pass just like a positive answer would.
                label = "NXDOMAIN" if outcome == _DNS_NXDOMAIN else "NODATA"
                log_q.put(("DEBUG",
                           f"DoH  {hostname} {qtype_name}: {label} "
                           f"(authoritative)  [{srv}]"))
                return outcome, data
            continue  # transport-level failure from this server — try next
        except ssl.SSLCertVerificationError as e:
            # A cert that fails verification is a distinct signal from a DPI
            # reset/timeout: the resolver either rotated to a cert without an
            # IP SAN, or the TLS connection is being intercepted by a MITM CA
            # trusted on this machine. Counted so the pass can flag it loudly.
            cert_failures += 1
            log_q.put(("DEBUG",
                       f"DoH  {srv}: certificate verification failed: {e}"))
            last_err = e
        except Exception as e:
            log_q.put(("DEBUG",
                       f"DoH  {srv} failed for {hostname} ({qtype_name}): "
                       f"{type(e).__name__}: {e}"))
            last_err = e
    if last_err is not None:
        if cert_failures:
            log_q.put(("WARNING",
                       f"TLS certificate verification failed for {cert_failures} "
                       f"DoH server(s) ({hostname}) — the resolver's certificate "
                       f"changed or the connection is being intercepted (TLS-MITM)"))
        else:
            log_q.put(("DEBUG",
                       f"All DoH servers exhausted for {hostname} "
                       f"({qtype_name}): {last_err}"))
    return _DNS_TRANSPORT_FAIL, None


def resolve_doh(hostname, use_doh, log_q):
    """DoH → public UDP → public TCP → AAAA → system DNS. Prefers IPv4;
    falls back to IPv6 for hosts that publish only AAAA.

    DoH answers arrive over verified TLS, so an authoritative negative from
    DoH ends the chain immediately: NXDOMAIN raises at once, and NODATA on
    the A query skips the pointless UDP/TCP A fallbacks and goes straight to
    AAAA. Unauthenticated negatives (plain UDP/TCP) never terminate the
    chain — a hostile network could inject them. The whole call is bounded
    by RESOLVE_BUDGET so a dead name cannot hang the calling CONNECT for
    many seconds.
    """
    if _is_ip(hostname):
        return hostname
    if not use_doh:
        info = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        for fam, _t, _p, _c, sa in info:
            if fam == socket.AF_INET:
                return sa[0]
        for fam, _t, _p, _c, sa in info:
            if fam == socket.AF_INET6:
                return sa[0]
        raise socket.gaierror(f"no usable address for {hostname}")

    cached = _cache_get(hostname)
    if cached is not None:
        return cached
    neg = _neg_cache_get(hostname)
    if neg is not None:
        log_q.put(("DEBUG", f"DNS negative cache hit for {hostname} ({neg})"))
        raise _negative_error(hostname, neg)

    deadline = time.monotonic() + RESOLVE_BUDGET
    # The A-side DoH pass gets at most half the budget, so a silently
    # dropped DoH path always leaves room for the UDP/TCP bypass stages.
    a_deadline = time.monotonic() + RESOLVE_BUDGET / 2

    # 1) DoH A — fragmented ClientHello to bypass DPI on resolver IPs.
    a_outcome, a_data = _doh_lookup(hostname, "A", _DNS_TYPE_A, log_q,
                                    deadline=a_deadline)
    if a_outcome == _DNS_OK:
        ip, ttl = a_data
        _cache_put(hostname, ip, ttl)
        return ip
    if a_outcome == _DNS_NXDOMAIN:
        # Authoritative, authenticated "no such name" — applies to every
        # record type, so no fallback can change the answer. Fail fast.
        _neg_cache_put(hostname, "nxdomain", a_data)
        log_q.put(("DEBUG", f"DoH NXDOMAIN for {hostname} — failing fast, no fallback"))
        raise _negative_error(hostname, "nxdomain")

    a_nodata = a_outcome == _DNS_NODATA
    if a_nodata:
        # The name exists but has no IPv4 — asking UDP/TCP for an A record
        # is pointless; go straight to the AAAA path.
        log_q.put(("DEBUG", f"DoH NODATA for {hostname} (A) — skipping to AAAA"))
    else:
        log_q.put(("WARNING",
                   f"All DoH servers failed ({hostname}): no A record  "
                   f"-> trying public UDP DNS"))

        # 2) Plain UDP DNS A to public resolvers.
        udp_a = _resolve_via_public_udp(hostname, log_q, qtype=_DNS_TYPE_A,
                                        deadline=deadline)
        if udp_a is not None:
            ip, ttl = udp_a
            _cache_put(hostname, ip, ttl)
            log_q.put(("INFO", f"Resolved {hostname} via public UDP DNS -> {ip}"))
            return ip

        # 3) Plain TCP DNS A — ISPs that rewrite UDP/53 often leave TCP/53 alone.
        tcp_a = _resolve_via_public_tcp(hostname, log_q, qtype=_DNS_TYPE_A,
                                        deadline=deadline)
        if tcp_a is not None:
            ip, ttl = tcp_a
            _cache_put(hostname, ip, ttl)
            log_q.put(("INFO", f"Resolved {hostname} via public TCP DNS -> {ip}"))
            return ip

    # 4) AAAA — IPv6-only hosts (e.g. ipv6.msftconnecttest.com).
    aaaa_outcome, aaaa_data = _doh_lookup(hostname, "AAAA", _DNS_TYPE_AAAA, log_q,
                                          deadline=deadline)
    if aaaa_outcome == _DNS_OK:
        ip, ttl = aaaa_data
        _cache_put(hostname, ip, ttl)
        log_q.put(("INFO", f"Resolved {hostname} via DoH (IPv6) -> {ip}"))
        return ip
    if aaaa_outcome == _DNS_NXDOMAIN:
        # RCODE 3 covers the whole name, not just AAAA — fail fast.
        _neg_cache_put(hostname, "nxdomain", aaaa_data)
        log_q.put(("DEBUG", f"DoH NXDOMAIN for {hostname} — failing fast, no fallback"))
        raise _negative_error(hostname, "nxdomain")
    if aaaa_outcome == _DNS_NODATA and a_nodata:
        # Both families authoritatively answered: the name exists but has
        # neither an A nor an AAAA record. Nothing below can change that.
        _neg_cache_put(hostname, "noaddr", min(a_data, aaaa_data))
        log_q.put(("DEBUG", f"DoH NODATA for {hostname} (A and AAAA) — no usable address"))
        raise _negative_error(hostname, "noaddr")
    # An AAAA NODATA while the A pass transport-failed is NOT conclusive —
    # the A side was never authoritatively answered — so keep falling back.
    udp_aaaa = _resolve_via_public_udp(hostname, log_q, qtype=_DNS_TYPE_AAAA,
                                       deadline=deadline)
    if udp_aaaa is not None:
        ip, ttl = udp_aaaa
        _cache_put(hostname, ip, ttl)
        log_q.put(("INFO", f"Resolved {hostname} via public UDP DNS (IPv6) -> {ip}"))
        return ip
    tcp_aaaa = _resolve_via_public_tcp(hostname, log_q, qtype=_DNS_TYPE_AAAA,
                                       deadline=deadline)
    if tcp_aaaa is not None:
        ip, ttl = tcp_aaaa
        _cache_put(hostname, ip, ttl)
        log_q.put(("INFO", f"Resolved {hostname} via public TCP DNS (IPv6) -> {ip}"))
        return ip

    log_q.put(("WARNING",
               f"Public DNS unavailable for {hostname}  -> system DNS"))

    # 5) Last resort — system resolver. getaddrinfo also sees AAAA, so
    #    AAAA-only hosts still resolve here. getaddrinfo cannot be
    #    timeboxed, so it only runs while the budget lasts; past the
    #    deadline, surface the failure instead of hanging.
    if time.monotonic() >= deadline:
        log_q.put(("DEBUG", f"DNS budget exhausted for {hostname} — skipping system resolver"))
        raise socket.gaierror(
            getattr(socket, "EAI_AGAIN", -3),
            f"could not resolve {hostname} within {RESOLVE_BUDGET:.0f}s")
    info = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    for fam, _t, _p, _c, sa in info:
        if fam == socket.AF_INET:
            return sa[0]
    for fam, _t, _p, _c, sa in info:
        if fam == socket.AF_INET6:
            return sa[0]
    raise socket.gaierror(f"no usable address for {hostname}")
