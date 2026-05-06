#!/usr/bin/env python3
"""
dpi_bypass.py — Lightweight SNI-based DPI bypass proxy
-------------------------------------------------------
How it works:
  1. Runs as a local HTTP proxy (CONNECT tunnel)
  2. Splits the TLS ClientHello into small TCP segments
     -> DPI never sees the full SNI field, so it lets the connection through
  3. Uses DNS-over-HTTPS (IP-based) to bypass DNS poisoning
  4. Pure Python, zero dependencies — runs natively on ARM64 and x86

Usage:
  Double-click dpi_bypass.bat  (Windows proxy is managed automatically)
  or: python dpi_bypass.py

Options:
  --port      Proxy listen port               (default: 8881)
  --fragment  ClientHello fragment size bytes (default: 2)
  --no-doh    Disable DoH, use system DNS
  --verbose   Enable debug logging
"""

import socket
import threading
import argparse
import logging
import urllib.request
import urllib.parse
import json
import ssl
import sys
import time
import re
import atexit
import ctypes
import winreg

# ── Helpers ───────────────────────────────────────────────────────────────────
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def _is_ip(host: str) -> bool:
    return bool(_IP_RE.match(host))

# Opener that bypasses the system proxy (i.e. ourselves) to avoid loops
_no_proxy_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

# ── Settings ──────────────────────────────────────────────────────────────────
DEFAULT_PORT    = 8881
FRAGMENT_SIZE   = 2       # bytes — smaller is better for DPI evasion
BUFFER          = 32768
CONNECT_TIMEOUT = 10      # seconds

# IP-based DoH servers — no domain resolution needed, immune to DNS poisoning
DOH_SERVERS = [
    "https://1.1.1.1/dns-query",   # Cloudflare primary
    "https://1.0.0.1/dns-query",   # Cloudflare secondary
    "https://8.8.8.8/dns-query",   # Google
    "https://9.9.9.9/dns-query",   # Quad9
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("dpi_bypass")

# ── DNS-over-HTTPS ────────────────────────────────────────────────────────────
_dns_cache: dict[str, tuple[str, float]] = {}
_dns_lock = threading.Lock()

def resolve_doh(hostname: str) -> str:
    """Resolve hostname via IP-based DoH with in-memory cache."""
    if _is_ip(hostname):
        return hostname

    with _dns_lock:
        if hostname in _dns_cache:
            ip, expires = _dns_cache[hostname]
            if time.time() < expires:
                return ip

    # SSL context: connecting by IP so hostname verification is disabled
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    last_err = None
    for server in DOH_SERVERS:
        try:
            url = f"{server}?name={urllib.parse.quote(hostname)}&type=A"
            req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
            with _no_proxy_opener.open(req, timeout=4) as resp:
                data = json.loads(resp.read())
            answers = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
            if not answers:
                continue
            ip = answers[0]
            ttl = data["Answer"][0].get("TTL", 60)
            with _dns_lock:
                _dns_cache[hostname] = (ip, time.time() + ttl)
            log.debug(f"DoH  {hostname} -> {ip}  [{server}]")
            return ip
        except Exception as e:
            last_err = e
            continue

    log.warning(f"All DoH servers failed ({hostname}): {last_err}  -> falling back to system DNS")
    return socket.gethostbyname(hostname)


# ── TCP connection + ClientHello fragmentation ────────────────────────────────
def connect_remote(host: str, port: int, use_doh: bool) -> socket.socket:
    ip = resolve_doh(host) if use_doh else socket.gethostbyname(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    # Nagle disabled — each send() becomes its own TCP segment (critical for fragmentation)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.connect((ip, port))
    sock.settimeout(None)
    return sock


def send_fragmented(sock: socket.socket, data: bytes, frag_size: int):
    """
    Send data in frag_size-byte chunks.
    With TCP_NODELAY on, each chunk becomes a separate TCP segment ->
    DPI never sees a single segment containing the full SNI.
    """
    offset = 0
    while offset < len(data):
        chunk = data[offset: offset + frag_size]
        sock.send(chunk)
        offset += frag_size


def is_tls_client_hello(data: bytes) -> bool:
    return len(data) > 5 and data[0] == 0x16 and data[1] == 0x03


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
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

    t1 = threading.Thread(target=pump, args=(a, b), daemon=True)
    t2 = threading.Thread(target=pump, args=(b, a), daemon=True)
    t1.start(); t2.start()
    t1.join();  t2.join()


# ── CONNECT tunnel (HTTPS) ────────────────────────────────────────────────────
def handle_connect(client: socket.socket, host: str, port: int, use_doh: bool, frag: int):
    try:
        remote = connect_remote(host, port, use_doh)
    except Exception as e:
        log.error(f"  Could not connect to {host}:{port} -> {e}")
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        client.close()
        return

    client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

    # Read first packet from client — almost certainly the TLS ClientHello
    try:
        first = client.recv(BUFFER)
    except OSError:
        client.close(); remote.close(); return

    if not first:
        client.close(); remote.close(); return

    if is_tls_client_hello(first):
        log.info(f"  [frag {frag}B]  {host}:{port}")
        send_fragmented(remote, first, frag)
    else:
        remote.sendall(first)

    relay(client, remote)


# ── Plain HTTP forwarding ─────────────────────────────────────────────────────
def handle_http(client: socket.socket, method: str, url: str,
                headers: bytes, use_doh: bool):
    stripped = url[7:] if url.startswith("http://") else url
    path_start = stripped.find("/")
    hostport = stripped[:path_start] if path_start != -1 else stripped
    path     = stripped[path_start:] if path_start != -1 else "/"

    if ":" in hostport:
        host, port_s = hostport.rsplit(":", 1)
        port = int(port_s)
    else:
        host, port = hostport, 80

    try:
        remote = connect_remote(host, port, use_doh)
        first_line = f"{method} {path} HTTP/1.1\r\n".encode()
        remote.sendall(first_line + headers)
        relay(client, remote)
    except Exception as e:
        log.error(f"  HTTP relay error: {e}")
        client.close()


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
                port = int(port_s)
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

def _refresh_windows_proxy():
    """Notify the system that proxy settings have changed."""
    try:
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
    except Exception:
        pass

def enable_windows_proxy(addr: str):
    """Enable the Windows system proxy and point it to addr. Returns old settings."""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE_SETTINGS,
                             0, winreg.KEY_READ | winreg.KEY_WRITE)
        try:
            old_enable = winreg.QueryValueEx(key, "ProxyEnable")[0]
            old_server = winreg.QueryValueEx(key, "ProxyServer")[0]
        except FileNotFoundError:
            old_enable, old_server = 0, ""
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, addr)
        winreg.CloseKey(key)
        _refresh_windows_proxy()
        log.info(f"Windows proxy ENABLED  ->  {addr}")
        return old_enable, old_server
    except Exception as e:
        log.warning(f"Could not enable proxy automatically: {e}")
        return None, None

def restore_windows_proxy(old_enable, old_server):
    """Restore Windows proxy settings to their previous state."""
    if old_enable is None:
        return
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE_SETTINGS,
                             0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, old_enable)
        if old_server:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, old_server)
        winreg.CloseKey(key)
        _refresh_windows_proxy()
        log.info("Windows proxy RESTORED.")
    except Exception as e:
        log.warning(f"Could not restore proxy settings: {e}")


# ── Shutdown handling ─────────────────────────────────────────────────────────
_shutdown_event = threading.Event()
_proxy_restore_args: tuple = (None, None)

def _do_shutdown():
    """Called on any exit path — always restores the Windows proxy."""
    _shutdown_event.set()
    restore_windows_proxy(*_proxy_restore_args)

def _win_console_handler(event):
    """
    Catches Windows console control events:
      0 = CTRL_C_EVENT, 1 = CTRL_BREAK_EVENT, 2 = CTRL_CLOSE_EVENT (X button)
    Returning False lets Windows proceed with its default action (closing the window).
    """
    _do_shutdown()
    return False

_HandlerRoutine = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)
_console_handler = _HandlerRoutine(_win_console_handler)


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Lightweight DPI bypass proxy — ARM64 native")
    parser.add_argument("--port",     type=int, default=DEFAULT_PORT,
                        help=f"Listen port (default: {DEFAULT_PORT})")
    parser.add_argument("--fragment", type=int, default=FRAGMENT_SIZE,
                        help=f"ClientHello fragment size in bytes (default: {FRAGMENT_SIZE})")
    parser.add_argument("--no-doh",  action="store_true",
                        help="Disable DNS-over-HTTPS, use system DNS")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    use_doh    = not args.no_doh
    proxy_addr = f"127.0.0.1:{args.port}"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", args.port))
    server.listen(256)
    server.settimeout(1.0)  # non-blocking accept loop so Ctrl+C is caught immediately

    old_enable, old_server_val = enable_windows_proxy(proxy_addr)

    global _proxy_restore_args
    _proxy_restore_args = (old_enable, old_server_val)
    atexit.register(_do_shutdown)                                          # normal exit
    ctypes.windll.kernel32.SetConsoleCtrlHandler(_console_handler, True)  # X button + Ctrl+C

    print(f"""
+------------------------------------------------------+
|        DPI Bypass Proxy  -  ARM64 compatible         |
+------------------------------------------------------+
|  Proxy address : 127.0.0.1:{args.port:<5}                    |
|  Fragment size : {args.fragment} bytes                              |
|  DoH (DNS)     : {"on  (via 1.1.1.1)              " if use_doh else "off (system DNS)             "}  |
|  Win proxy     : managed automatically               |
+------------------------------------------------------+
|  Close this window or press Ctrl+C to stop.         |
|  Proxy settings will be restored automatically.     |
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
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        _do_shutdown()


if __name__ == "__main__":
    main()
