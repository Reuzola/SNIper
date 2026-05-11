#!/usr/bin/env python3
"""
dpi_bypass.py — Lightweight SNI-based DPI bypass proxy
-------------------------------------------------------
How it works:
  1. Runs as a local HTTP proxy (CONNECT tunnel)
  2. Splits the TLS ClientHello into small TCP segments
     -> DPI never sees the full SNI field, so it lets the connection through
  3. Resolves names via DNS-over-HTTPS; if DoH endpoints are unreachable,
     falls back to plain UDP DNS aimed at public resolvers (1.1.1.1,
     8.8.8.8, 9.9.9.9); only as a last resort uses the (possibly poisoned)
     system DNS
  4. Pure Python, zero dependencies — pure user-space, no admin rights,
     no kernel drivers, no TAP adapters

Usage:
  python dpi_bypass.py
  (or run the packaged GUI executable — see README)

Options:
  --port      Proxy listen port               (default: 8881)
  --fragment  ClientHello fragment size bytes (default: 2)
  --no-doh    Disable DoH, use system DNS
  --verbose   Enable debug logging
"""

import socket
import sys
import threading
import argparse
import logging
import urllib.request
import urllib.parse
import json
import ssl
import time
import re
import atexit
import ctypes
import struct
import random
from collections import OrderedDict

try:
    import winreg
    _IS_WINDOWS = True
except ImportError:
    _IS_WINDOWS = False

# ── Helpers ───────────────────────────────────────────────────────────────────
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def _is_ip(host: str) -> bool:
    return bool(_IP_RE.match(host))

# SSL context for DoH. We connect to DoH servers BY IP, but their certificates
# include the IP in the SAN, so default verification works. Built once and
# reused (cheaper than rebuilding per request).
#
# ALPN must be advertised explicitly. Without it, some Python builds send no
# ALPN at all, and the DoH server then assumes HTTP/2 — Python's stdlib only
# speaks HTTP/1.1, so the server replies with 505 "HTTP Version Not Supported".
_doh_ssl_ctx = ssl.create_default_context()
try:
    _doh_ssl_ctx.set_alpn_protocols(["http/1.1"])
except (NotImplementedError, AttributeError):
    pass  # very old OpenSSL — skip ALPN

# Opener that:
#   1. Bypasses the system proxy (i.e. ourselves) to avoid loops
#   2. Uses our DoH SSL context for HTTPS — note that OpenerDirector.open()
#      does NOT accept a `context` kwarg, so we must wire it in via the
#      HTTPSHandler at build time.
_no_proxy_opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=_doh_ssl_ctx),
)

# ── Settings ──────────────────────────────────────────────────────────────────
DEFAULT_PORT    = 8881
FRAGMENT_SIZE   = 2       # bytes — smaller is better for DPI evasion
BUFFER          = 32768
CONNECT_TIMEOUT = 10      # seconds
DOH_TIMEOUT     = 4       # seconds
UDP_DNS_TIMEOUT = 2.0     # seconds — short, we retry across servers
DNS_CACHE_MAX   = 1024    # entries — bound the cache to avoid unbounded growth

# IP-based DoH servers — no domain resolution needed, immune to DNS poisoning
DOH_SERVERS = [
    "https://1.1.1.1/dns-query",   # Cloudflare primary
    "https://1.0.0.1/dns-query",   # Cloudflare secondary
    "https://8.8.8.8/dns-query",   # Google
    "https://9.9.9.9/dns-query",   # Quad9
]

# Plain UDP DNS resolvers — used when DoH endpoints are blocked at the
# network level (common with ISP-level DPI that interferes with TLS to
# well-known DoH IPs). Many ISPs only poison responses from their *own*
# resolver and pass UDP/53 traffic to other IPs through untouched.
PLAIN_DNS_SERVERS = [
    "1.1.1.1",        # Cloudflare
    "8.8.8.8",        # Google
    "9.9.9.9",        # Quad9
    "1.0.0.1",        # Cloudflare secondary
    "8.8.4.4",        # Google secondary
    "208.67.222.222", # OpenDNS
]

# Hop-by-hop headers that proxies must strip before forwarding (RFC 7230 §6.1)
_HOP_BY_HOP = {
    b"connection", b"keep-alive", b"proxy-authenticate", b"proxy-authorization",
    b"proxy-connection", b"te", b"trailer", b"transfer-encoding", b"upgrade",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("dpi_bypass")

# ── DNS-over-HTTPS ────────────────────────────────────────────────────────────
# OrderedDict so we can evict in FIFO order when DNS_CACHE_MAX is reached.
_dns_cache: "OrderedDict[str, tuple[str, float]]" = OrderedDict()
_dns_lock = threading.Lock()


def _cache_get(hostname: str):
    with _dns_lock:
        entry = _dns_cache.get(hostname)
        if entry is None:
            return None
        ip, expires = entry
        if time.time() >= expires:
            _dns_cache.pop(hostname, None)
            return None
        # Refresh recency for simple LRU behaviour
        _dns_cache.move_to_end(hostname)
        return ip


def _cache_put(hostname: str, ip: str, ttl: float):
    with _dns_lock:
        _dns_cache[hostname] = (ip, time.time() + ttl)
        _dns_cache.move_to_end(hostname)
        while len(_dns_cache) > DNS_CACHE_MAX:
            _dns_cache.popitem(last=False)


# ── Plain UDP DNS (RFC 1035) ──────────────────────────────────────────────────
# RR type numbers we actually use
_DNS_TYPE_A    = 1
_DNS_TYPE_AAAA = 28


def _build_dns_query(hostname: str, tid: int, qtype: int = _DNS_TYPE_A) -> bytes:
    """Encode a minimal query packet (A or AAAA) for the given hostname."""
    # Header: id, flags=RD, qd=1, an=ns=ar=0
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in hostname.encode("ascii").split(b"."):
        if not part:
            continue
        if len(part) > 63:
            raise ValueError("DNS label too long")
        qname += bytes([len(part)]) + part
    qname += b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS=IN
    return header + question


def _skip_name(buf: bytes, off: int) -> int:
    """Advance past a (possibly compressed) DNS name; return new offset."""
    while off < len(buf):
        l = buf[off]
        if l == 0:
            return off + 1
        if l & 0xC0 == 0xC0:
            return off + 2  # pointer — 2 bytes total
        off += 1 + l
    return off


def _parse_dns_response(buf: bytes, expected_tid: int, want_type: int = _DNS_TYPE_A):
    """Return (ip, ttl) for the first record of want_type, or None on failure."""
    if len(buf) < 12:
        return None
    tid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", buf[:12])
    if tid != expected_tid:
        return None
    if (flags & 0x000F) != 0:           # non-zero RCODE = error
        return None
    if an == 0:
        return None
    off = 12
    # Skip question section
    for _ in range(qd):
        off = _skip_name(buf, off)
        off += 4  # QTYPE + QCLASS
    # Walk answers — skip CNAMEs and unrelated types, return first match.
    for _ in range(an):
        if off >= len(buf):
            return None
        off = _skip_name(buf, off)
        if off + 10 > len(buf):
            return None
        rtype, _rclass, ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        if off + rdlen > len(buf):
            return None
        if rtype == want_type:
            if want_type == _DNS_TYPE_A and rdlen == 4:
                ip = ".".join(str(b) for b in buf[off:off + 4])
                return ip, int(ttl)
            if want_type == _DNS_TYPE_AAAA and rdlen == 16:
                ip = socket.inet_ntop(socket.AF_INET6, buf[off:off + 16])
                return ip, int(ttl)
        off += rdlen
    return None


def _udp_dns_query(hostname: str, server_ip: str,
                   qtype: int = _DNS_TYPE_A,
                   timeout: float = UDP_DNS_TIMEOUT):
    """Send one A/AAAA query over UDP/53; return (ip, ttl) or None."""
    tid = random.randint(0, 0xFFFF)
    pkt = _build_dns_query(hostname, tid, qtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(pkt, (server_ip, 53))
        # AAAA responses can exceed the classic 512-byte UDP DNS limit on
        # hosts with many addresses; 2048 covers any realistic answer set.
        resp, _addr = s.recvfrom(2048)
    except OSError:
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass
    return _parse_dns_response(resp, tid, qtype)


def _resolve_via_public_udp(hostname: str, qtype: int = _DNS_TYPE_A):
    """Try plain UDP DNS against public resolvers. Returns (ip, ttl) or None."""
    for srv in PLAIN_DNS_SERVERS:
        result = _udp_dns_query(hostname, srv, qtype=qtype)
        if result is not None:
            ip, ttl = result
            log.debug(f"UDP-DNS  {hostname} -> {ip}  [{srv}]")
            return ip, max(int(ttl), 30)
    return None


def _doh_lookup(hostname: str, qtype_name: str, qtype_num: int):
    """One DoH pass over all configured servers. Returns (ip, ttl) or None."""
    last_err: Exception | None = None
    for server in DOH_SERVERS:
        try:
            url = f"{server}?name={urllib.parse.quote(hostname)}&type={qtype_name}"
            # Some local middleware (HTTPS-scanning AV, captive portals)
            # rejects requests without a User-Agent; add a plausible one.
            req = urllib.request.Request(url, headers={
                "Accept":     "application/dns-json",
                "User-Agent": "Mozilla/5.0 dpi_bypass/1.0",
            })
            with _no_proxy_opener.open(req, timeout=DOH_TIMEOUT) as resp:
                data = json.loads(resp.read())
            records = [(a["data"], a.get("TTL", 60))
                       for a in data.get("Answer", [])
                       if a.get("type") == qtype_num and "data" in a]
            if not records:
                continue
            ip, ttl = records[0]
            log.debug(f"DoH  {hostname} {qtype_name} -> {ip}  [{server}]")
            return ip, max(int(ttl), 30)
        except Exception as e:
            log.debug(f"DoH  {server} failed for {hostname} ({qtype_name}): "
                      f"{type(e).__name__}: {e}")
            last_err = e
            continue
    if last_err is not None:
        log.debug(f"All DoH servers exhausted for {hostname} ({qtype_name}): {last_err}")
    return None


def resolve_doh(hostname: str) -> str:
    """Resolve hostname via (DoH → public UDP → system DNS), preferring IPv4.

    Tries A records via DoH then public UDP; if no A is available anywhere,
    repeats the chain for AAAA so IPv6-only hosts (e.g. Windows's
    ipv6.msftconnecttest.com) still resolve. Falls back to getaddrinfo
    as a last resort — covers system DNS for both address families.
    """
    if _is_ip(hostname):
        return hostname

    cached = _cache_get(hostname)
    if cached is not None:
        return cached

    # 1) DoH A
    doh_a = _doh_lookup(hostname, "A", _DNS_TYPE_A)
    if doh_a is not None:
        ip, ttl = doh_a
        _cache_put(hostname, ip, ttl)
        return ip

    log.warning(f"All DoH servers failed ({hostname}): no A record  -> trying public UDP DNS")

    # 2) Plain UDP DNS A to public resolvers — bypasses ISP DoH blocks while
    #    still avoiding the local poisoned resolver.
    udp_a = _resolve_via_public_udp(hostname, qtype=_DNS_TYPE_A)
    if udp_a is not None:
        ip, ttl = udp_a
        _cache_put(hostname, ip, ttl)
        log.info(f"Resolved {hostname} via public UDP DNS -> {ip}")
        return ip

    # 3) No A records anywhere — try AAAA (IPv6-only hosts like
    #    ipv6.msftconnecttest.com). DoH first, then UDP.
    doh_aaaa = _doh_lookup(hostname, "AAAA", _DNS_TYPE_AAAA)
    if doh_aaaa is not None:
        ip, ttl = doh_aaaa
        _cache_put(hostname, ip, ttl)
        log.info(f"Resolved {hostname} via DoH (IPv6) -> {ip}")
        return ip
    udp_aaaa = _resolve_via_public_udp(hostname, qtype=_DNS_TYPE_AAAA)
    if udp_aaaa is not None:
        ip, ttl = udp_aaaa
        _cache_put(hostname, ip, ttl)
        log.info(f"Resolved {hostname} via public UDP DNS (IPv6) -> {ip}")
        return ip

    log.warning(f"Public DNS unavailable for {hostname}  -> falling back to system DNS")

    # 4) Last resort — system resolver. Use getaddrinfo so we also see AAAA
    #    when the host has no A record. Prefer IPv4 when both exist.
    try:
        info = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        # Re-raise as gethostbyname would, so callers see the same error class.
        raise
    for fam, _t, _p, _c, sa in info:
        if fam == socket.AF_INET:
            return sa[0]
    for fam, _t, _p, _c, sa in info:
        if fam == socket.AF_INET6:
            return sa[0]
    raise socket.gaierror(f"no usable address for {hostname}")


# ── TCP connection + ClientHello fragmentation ────────────────────────────────
def _resolve_for_connect(host: str, use_doh: bool) -> str:
    """Pick a resolution strategy. With DoH off, getaddrinfo so AAAA-only
    hosts still resolve through system DNS."""
    if use_doh:
        return resolve_doh(host)
    info = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    for fam, _t, _p, _c, sa in info:
        if fam == socket.AF_INET:
            return sa[0]
    for fam, _t, _p, _c, sa in info:
        if fam == socket.AF_INET6:
            return sa[0]
    raise socket.gaierror(f"no usable address for {host}")


def connect_remote(host: str, port: int, use_doh: bool) -> socket.socket:
    ip = _resolve_for_connect(host, use_doh)
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(CONNECT_TIMEOUT)
        # Nagle disabled — each send() becomes its own TCP segment (critical for fragmentation)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect((ip, port))
        sock.settimeout(None)
    except Exception:
        # Make sure we don't leak a half-open socket on failure
        try:
            sock.close()
        except OSError:
            pass
        raise
    return sock


def send_fragmented(sock: socket.socket, data: bytes, frag_size: int):
    """
    Send data in frag_size-byte chunks.
    With TCP_NODELAY on, each chunk becomes a separate TCP segment ->
    DPI never sees a single segment containing the full SNI.

    We loop on send() inside each chunk so a short write doesn't drop bytes,
    but we don't merge across chunks (which would defeat fragmentation).
    """
    if frag_size < 1:
        frag_size = 1
    offset = 0
    n = len(data)
    while offset < n:
        end = min(offset + frag_size, n)
        chunk_off = offset
        while chunk_off < end:
            sent = sock.send(data[chunk_off:end])
            if sent == 0:
                raise OSError("socket closed during fragmented send")
            chunk_off += sent
        offset = end


def is_tls_client_hello(data: bytes) -> bool:
    # Record type 0x16 (handshake) + version major 0x03 + handshake type 0x01 (ClientHello)
    return len(data) > 5 and data[0] == 0x16 and data[1] == 0x03 and data[5] == 0x01


# ── Bidirectional relay ───────────────────────────────────────────────────────
def relay(a: socket.socket, b: socket.socket):
    """Forward data between two sockets in both directions."""
    def pump(src, dst):
        try:
            while True:
                chunk = src.recv(BUFFER)
                if not chunk:
                    break
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            # Signal EOF in the direction we just finished pumping.
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t1 = threading.Thread(target=pump, args=(a, b), daemon=True)
    t2 = threading.Thread(target=pump, args=(b, a), daemon=True)
    t1.start(); t2.start()
    t1.join();  t2.join()


# ── CONNECT tunnel (HTTPS) ────────────────────────────────────────────────────
def handle_connect(client: socket.socket, host: str, port: int, use_doh: bool, frag: int):
    remote = None
    try:
        try:
            remote = connect_remote(host, port, use_doh)
        except Exception as e:
            log.error(f"  Could not connect to {host}:{port} -> {e}")
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except OSError:
                pass
            return

        try:
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        except OSError:
            return

        # Read first packet from client — almost certainly the TLS ClientHello
        try:
            first = client.recv(BUFFER)
        except OSError:
            return
        if not first:
            return

        try:
            if is_tls_client_hello(first):
                log.info(f"  [frag {frag}B]  {host}:{port}")
                send_fragmented(remote, first, frag)
            else:
                remote.sendall(first)
        except OSError as e:
            log.debug(f"  initial send failed for {host}:{port}: {e}")
            return

        relay(client, remote)
    finally:
        if remote is not None:
            try:
                remote.close()
            except OSError:
                pass


# ── Plain HTTP forwarding ─────────────────────────────────────────────────────
def _strip_hop_by_hop(headers_block: bytes) -> bytes:
    """Remove hop-by-hop headers from a raw header block (lines + trailing CRLFCRLF)."""
    if not headers_block.endswith(b"\r\n\r\n"):
        return headers_block
    body_split = headers_block[:-4]
    out_lines = []
    for line in body_split.split(b"\r\n"):
        name, sep, _ = line.partition(b":")
        if sep and name.strip().lower() in _HOP_BY_HOP:
            continue
        out_lines.append(line)
    return b"\r\n".join(out_lines) + b"\r\n\r\n"


def handle_http(client: socket.socket, method: str, url: str,
                headers: bytes, use_doh: bool):
    stripped = url[7:] if url.startswith("http://") else url
    path_start = stripped.find("/")
    hostport = stripped[:path_start] if path_start != -1 else stripped
    path     = stripped[path_start:] if path_start != -1 else "/"

    if ":" in hostport:
        host, port_s = hostport.rsplit(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            log.error(f"  Bad port in URL: {url[:80]}")
            return
    else:
        host, port = hostport, 80

    remote = None
    try:
        remote = connect_remote(host, port, use_doh)
        first_line = f"{method} {path} HTTP/1.1\r\n".encode()
        remote.sendall(first_line + _strip_hop_by_hop(headers))
        relay(client, remote)
    except Exception as e:
        log.error(f"  HTTP relay error: {e}")
    finally:
        if remote is not None:
            try:
                remote.close()
            except OSError:
                pass


# ── Client handler ────────────────────────────────────────────────────────────
def handle_client(client: socket.socket, addr, use_doh: bool, frag: int):
    try:
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = client.recv(BUFFER)
            if not chunk:
                return
            raw += chunk
            if len(raw) > 65536:
                log.debug("oversized request header — dropping")
                return

        header_block, _, body = raw.partition(b"\r\n\r\n")
        lines = header_block.split(b"\r\n")
        first_line = lines[0].decode(errors="replace")
        parts = first_line.split(" ", 2)
        if len(parts) < 2:
            return
        method, url = parts[0], parts[1]
        rest_headers = b"\r\n".join(lines[1:]) + b"\r\n\r\n"

        if method.upper() == "CONNECT":
            if ":" in url:
                host, port_s = url.rsplit(":", 1)
                try:
                    port = int(port_s)
                except ValueError:
                    return
            else:
                host, port = url, 443
            log.info(f"CONNECT  {host}:{port}")
            handle_connect(client, host, port, use_doh, frag)
        else:
            log.info(f"{method}  {url[:80]}")
            handle_http(client, method, url, rest_headers + body, use_doh)

    except Exception as e:
        log.debug(f"handle_client error: {e}")
    finally:
        try:
            client.close()
        except OSError:
            pass


# ── Windows proxy management ──────────────────────────────────────────────────
_IE_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# Holds the values needed to restore the system proxy. Set BEFORE any change is
# made so a Ctrl+C arriving mid-write still has something to restore.
_proxy_restore_args: tuple = (None, None)
_proxy_restored = threading.Event()


def _refresh_windows_proxy():
    """Notify the system that proxy settings have changed."""
    if not _IS_WINDOWS:
        return
    try:
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
    except Exception:
        pass


def enable_windows_proxy(addr: str):
    """Enable the Windows system proxy and point it to addr.

    Saves the prior settings into the module-level restore tuple BEFORE any
    write, so an interrupt mid-call can still be cleaned up by atexit.
    Returns the saved (old_enable, old_server) pair.
    """
    global _proxy_restore_args
    if not _IS_WINDOWS:
        log.warning("Not running on Windows — system proxy is not managed automatically.")
        return None, None
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE_SETTINGS,
                             0, winreg.KEY_READ | winreg.KEY_WRITE)
        try:
            try:
                old_enable = winreg.QueryValueEx(key, "ProxyEnable")[0]
            except FileNotFoundError:
                old_enable = 0
            try:
                old_server = winreg.QueryValueEx(key, "ProxyServer")[0]
            except FileNotFoundError:
                old_server = ""

            # Save BEFORE we modify, so cleanup always has correct values.
            _proxy_restore_args = (old_enable, old_server)
            _proxy_restored.clear()

            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, addr)
        finally:
            winreg.CloseKey(key)
        _refresh_windows_proxy()
        log.info(f"Windows proxy ENABLED  ->  {addr}")
        return old_enable, old_server
    except Exception as e:
        log.warning(f"Could not enable proxy automatically: {e}")
        return None, None


def restore_windows_proxy(old_enable, old_server):
    """Restore Windows proxy settings to their previous state (idempotent)."""
    if not _IS_WINDOWS:
        return
    if old_enable is None:
        return
    if _proxy_restored.is_set():
        return
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE_SETTINGS,
                             0, winreg.KEY_WRITE)
        try:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(old_enable))
            # Always write ProxyServer back — even an empty string is the
            # correct "no upstream" state and prevents leaving our address behind.
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, old_server or "")
        finally:
            winreg.CloseKey(key)
        _refresh_windows_proxy()
        _proxy_restored.set()
        log.info("Windows proxy RESTORED.")
    except Exception as e:
        log.warning(f"Could not restore proxy settings: {e}")


# ── Shutdown handling ─────────────────────────────────────────────────────────
_shutdown_event = threading.Event()


def _do_shutdown():
    """Called on any exit path — always restores the Windows proxy."""
    _shutdown_event.set()
    restore_windows_proxy(*_proxy_restore_args)


def _win_console_handler(event):
    """
    Catches Windows console control events:
      0 = CTRL_C_EVENT, 1 = CTRL_BREAK_EVENT, 2 = CTRL_CLOSE_EVENT (X button),
      5 = CTRL_LOGOFF_EVENT, 6 = CTRL_SHUTDOWN_EVENT
    Returning False lets Windows proceed with its default action.
    """
    _do_shutdown()
    return False


_HandlerRoutine = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint) if _IS_WINDOWS else None
_console_handler = _HandlerRoutine(_win_console_handler) if _IS_WINDOWS else None


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Lightweight DPI bypass proxy — runs in user-space, no admin rights required")
    parser.add_argument("--port",     type=int, default=DEFAULT_PORT,
                        help=f"Listen port (default: {DEFAULT_PORT})")
    parser.add_argument("--fragment", type=int, default=FRAGMENT_SIZE,
                        help=f"ClientHello fragment size in bytes (default: {FRAGMENT_SIZE})")
    parser.add_argument("--no-doh",  action="store_true",
                        help="Disable DNS-over-HTTPS, use system DNS")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    if not (1 <= args.port <= 65535):
        parser.error("--port must be between 1 and 65535")
    if not (1 <= args.fragment <= 512):
        parser.error("--fragment must be between 1 and 512")

    if args.verbose:
        log.setLevel(logging.DEBUG)

    use_doh    = not args.no_doh
    proxy_addr = f"127.0.0.1:{args.port}"

    # Register cleanup BEFORE we touch system settings so any failure between
    # here and accept() still triggers a proxy restore.
    atexit.register(_do_shutdown)
    if _IS_WINDOWS:
        ctypes.windll.kernel32.SetConsoleCtrlHandler(_console_handler, True)

    # Bind early so a port conflict fails before we touch the system proxy.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("127.0.0.1", args.port))
    except OSError as e:
        log.error(f"Could not bind to 127.0.0.1:{args.port} -> {e}")
        server.close()
        sys.exit(1)
    server.listen(256)
    server.settimeout(1.0)  # non-blocking accept loop so Ctrl+C is caught immediately

    enable_windows_proxy(proxy_addr)

    doh_line = "on  (via 1.1.1.1)" if use_doh else "off (system DNS)"
    print(f"""
+------------------------------------------------------+
|     DPI Bypass Proxy  -  user-space, no admin        |
+------------------------------------------------------+
|  Proxy address : 127.0.0.1:{args.port}
|  Fragment size : {args.fragment} bytes
|  DoH (DNS)     : {doh_line}
|  Win proxy     : managed automatically (HKCU only)
+------------------------------------------------------+
|  Close this window or press Ctrl+C to stop.
|  Proxy settings will be restored automatically.
+------------------------------------------------------+
""")

    log.info("Listening for connections...")

    try:
        while not _shutdown_event.is_set():
            try:
                client, addr = server.accept()
                t = threading.Thread(
                    target=handle_client,
                    args=(client, addr, use_doh, args.fragment),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue
            except OSError as e:
                if not _shutdown_event.is_set():
                    log.error(f"accept error: {e}")
                else:
                    break
    except KeyboardInterrupt:
        pass
    finally:
        try:
            server.close()
        except OSError:
            pass
        _do_shutdown()


if __name__ == "__main__":
    main()
