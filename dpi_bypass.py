#!/usr/bin/env python3
"""
dpi_bypass.py — Lightweight SNI-based DPI bypass proxy
-------------------------------------------------------
How it works:
  1. Runs as a local HTTP proxy (CONNECT tunnel)
  2. Splits the TLS ClientHello into small TCP segments
     -> DPI never sees the full SNI field, so it lets the connection through
  3. Uses DNS-over-HTTPS (IP-based) to bypass DNS poisoning
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
DNS_CACHE_MAX   = 1024    # entries — bound the cache to avoid unbounded growth

# IP-based DoH servers — no domain resolution needed, immune to DNS poisoning
DOH_SERVERS = [
    "https://1.1.1.1/dns-query",   # Cloudflare primary
    "https://1.0.0.1/dns-query",   # Cloudflare secondary
    "https://8.8.8.8/dns-query",   # Google
    "https://9.9.9.9/dns-query",   # Quad9
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


def resolve_doh(hostname: str) -> str:
    """Resolve hostname via IP-based DoH with in-memory cache."""
    if _is_ip(hostname):
        return hostname

    cached = _cache_get(hostname)
    if cached is not None:
        return cached

    last_err: Exception | None = None
    for server in DOH_SERVERS:
        try:
            url = f"{server}?name={urllib.parse.quote(hostname)}&type=A"
            # Some local middleware (HTTPS-scanning AV, captive portals)
            # rejects requests without a User-Agent; add a plausible one.
            req = urllib.request.Request(url, headers={
                "Accept":     "application/dns-json",
                "User-Agent": "Mozilla/5.0 dpi_bypass/1.0",
            })
            with _no_proxy_opener.open(req, timeout=DOH_TIMEOUT) as resp:
                data = json.loads(resp.read())
            # Filter to A records (type 1) and pair each IP with its own TTL.
            a_records = [(a["data"], a.get("TTL", 60))
                         for a in data.get("Answer", [])
                         if a.get("type") == 1 and "data" in a]
            if not a_records:
                continue
            ip, ttl = a_records[0]
            ttl = max(int(ttl), 30)  # clamp tiny TTLs to avoid thrashing
            _cache_put(hostname, ip, ttl)
            log.debug(f"DoH  {hostname} -> {ip}  [{server}]")
            return ip
        except Exception as e:
            log.debug(f"DoH  {server} failed for {hostname}: {type(e).__name__}: {e}")
            last_err = e
            continue

    log.warning(f"All DoH servers failed ({hostname}): {last_err}  -> falling back to system DNS")
    return socket.gethostbyname(hostname)


# ── TCP connection + ClientHello fragmentation ────────────────────────────────
def connect_remote(host: str, port: int, use_doh: bool) -> socket.socket:
    ip = resolve_doh(host) if use_doh else socket.gethostbyname(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
