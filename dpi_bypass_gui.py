#!/usr/bin/env python3
"""
dpi_bypass_gui.py — modern GUI front-end for the DPI bypass proxy.

All proxy logic is embedded; no separate file needed.
Requires only the Python standard library (tkinter, ctypes — both ship with
CPython on Windows). The system-tray icon is implemented directly against
the Win32 Shell_NotifyIcon API so no third-party packages are needed.

Runs entirely at the application layer: the proxy listens on 127.0.0.1, the
Windows system proxy is toggled via HKEY_CURRENT_USER, and ClientHello
fragmentation is a userland send() pattern. No admin rights, no kernel
drivers, no service install — launching from a non-elevated shell never
triggers a UAC prompt. Packaged as a portable single-file EXE via PyInstaller
(see build_exe.bat).
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import socket
import urllib.request
import urllib.parse
import json
import ssl
import time
import re
import queue
import ctypes
import atexit
import struct
import random
from collections import OrderedDict

try:
    import winreg
    _IS_WINDOWS = True
except ImportError:
    _IS_WINDOWS = False


# ─────────────────────────────────────────────────────────────────────────────
#  High-DPI awareness — must run BEFORE any Tk window is created.
# ─────────────────────────────────────────────────────────────────────────────
def _enable_high_dpi():
    if not _IS_WINDOWS:
        return
    try:
        # Per-Monitor v2 (Win10 1703+). Best result on modern systems.
        ctypes.windll.user32.SetProcessDpiAwarenessContext(
            ctypes.c_void_p(-4)
        )
        return
    except (AttributeError, OSError):
        pass
    try:
        # Per-Monitor v1 (Win 8.1+).
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return
    except (AttributeError, OSError):
        pass
    try:
        # System DPI aware (Vista+).
        ctypes.windll.user32.SetProcessDPIAware()
    except (AttributeError, OSError):
        pass


_enable_high_dpi()


# ─────────────────────────────────────────────────────────────────────────────
#  Proxy core (identical to dpi_bypass.py — UNCHANGED logic)
# ─────────────────────────────────────────────────────────────────────────────
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
def _is_ip(h): return bool(_IP_RE.match(h))

_doh_ssl_ctx = ssl.create_default_context()
try:
    _doh_ssl_ctx.set_alpn_protocols(["http/1.1"])
except (NotImplementedError, AttributeError):
    pass
_no_proxy_opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=_doh_ssl_ctx),
)

BUFFER          = 32768
CONNECT_TIMEOUT = 10
DOH_TIMEOUT     = 4
UDP_DNS_TIMEOUT = 2.0
DNS_CACHE_MAX   = 1024
DOH_SERVERS = [
    "https://1.1.1.1/dns-query",
    "https://1.0.0.1/dns-query",
    "https://8.8.8.8/dns-query",
    "https://9.9.9.9/dns-query",
]
# Plain UDP DNS resolvers — used when DoH endpoints are blocked at the
# network level (common with ISP-level DPI that interferes with TLS to
# well-known DoH IPs). Most ISPs only poison responses from their *own*
# resolver and pass UDP/53 traffic to other IPs through untouched.
PLAIN_DNS_SERVERS = [
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
    "1.0.0.1",
    "8.8.4.4",
    "208.67.222.222",
]

_HOP_BY_HOP = {
    b"connection", b"keep-alive", b"proxy-authenticate", b"proxy-authorization",
    b"proxy-connection", b"te", b"trailer", b"transfer-encoding", b"upgrade",
}

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


# ── Plain UDP DNS (RFC 1035) — fallback when DoH endpoints are blocked ──────
_DNS_TYPE_A    = 1
_DNS_TYPE_AAAA = 28


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


def _parse_dns_response(buf, expected_tid, want_type=_DNS_TYPE_A):
    if len(buf) < 12:
        return None
    tid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", buf[:12])
    if tid != expected_tid:
        return None
    if (flags & 0x000F) != 0:
        return None
    if an == 0:
        return None
    off = 12
    for _ in range(qd):
        off = _skip_name(buf, off)
        off += 4
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
                return ".".join(str(b) for b in buf[off:off + 4]), int(ttl)
            if want_type == _DNS_TYPE_AAAA and rdlen == 16:
                return socket.inet_ntop(socket.AF_INET6, buf[off:off + 16]), int(ttl)
        off += rdlen
    return None


def _udp_dns_query(hostname, server_ip, qtype=_DNS_TYPE_A, timeout=UDP_DNS_TIMEOUT):
    tid = random.randint(0, 0xFFFF)
    pkt = _build_dns_query(hostname, tid, qtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(pkt, (server_ip, 53))
        resp, _addr = s.recvfrom(2048)
    except OSError:
        return None
    finally:
        try: s.close()
        except OSError: pass
    return _parse_dns_response(resp, tid, qtype)


def _resolve_via_public_udp(hostname, log_q, qtype=_DNS_TYPE_A):
    for srv in PLAIN_DNS_SERVERS:
        result = _udp_dns_query(hostname, srv, qtype=qtype)
        if result is not None:
            ip, ttl = result
            log_q.put(("DEBUG", f"UDP-DNS  {hostname} -> {ip}  [{srv}]"))
            return ip, max(int(ttl), 30)
        else:
            log_q.put(("DEBUG", f"UDP-DNS  {srv} failed for {hostname}"))
    return None


def _doh_lookup(hostname, qtype_name, qtype_num, log_q):
    """One DoH pass over all configured servers. Returns (ip, ttl) or None."""
    last_err = None
    for srv in DOH_SERVERS:
        try:
            url = f"{srv}?name={urllib.parse.quote(hostname)}&type={qtype_name}"
            req = urllib.request.Request(url, headers={
                "Accept":     "application/dns-json",
                "User-Agent": "Mozilla/5.0 dpi_bypass/1.0",
            })
            with _no_proxy_opener.open(req, timeout=DOH_TIMEOUT) as r:
                data = json.loads(r.read())
            records = [(a["data"], a.get("TTL", 60))
                       for a in data.get("Answer", [])
                       if a.get("type") == qtype_num and "data" in a]
            if not records:
                continue
            ip, ttl = records[0]
            return ip, max(int(ttl), 30)
        except Exception as e:
            log_q.put(("DEBUG",
                       f"DoH  {srv} failed for {hostname} ({qtype_name}): "
                       f"{type(e).__name__}: {e}"))
            last_err = e
    return None


def resolve_doh(hostname, use_doh, log_q):
    """DoH → public UDP → AAAA → system DNS. Prefers IPv4; falls back to IPv6
    for hosts that publish only AAAA (e.g. ipv6.msftconnecttest.com)."""
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

    # 1) DoH A
    doh_a = _doh_lookup(hostname, "A", _DNS_TYPE_A, log_q)
    if doh_a is not None:
        ip, ttl = doh_a
        _cache_put(hostname, ip, ttl)
        return ip

    log_q.put(("WARNING",
               f"All DoH servers failed ({hostname}): no A record  "
               f"-> trying public UDP DNS"))

    # 2) Plain UDP DNS A to public resolvers.
    udp_a = _resolve_via_public_udp(hostname, log_q, qtype=_DNS_TYPE_A)
    if udp_a is not None:
        ip, ttl = udp_a
        _cache_put(hostname, ip, ttl)
        log_q.put(("INFO", f"Resolved {hostname} via public UDP DNS -> {ip}"))
        return ip

    # 3) AAAA — IPv6-only hosts (e.g. ipv6.msftconnecttest.com).
    doh_aaaa = _doh_lookup(hostname, "AAAA", _DNS_TYPE_AAAA, log_q)
    if doh_aaaa is not None:
        ip, ttl = doh_aaaa
        _cache_put(hostname, ip, ttl)
        log_q.put(("INFO", f"Resolved {hostname} via DoH (IPv6) -> {ip}"))
        return ip
    udp_aaaa = _resolve_via_public_udp(hostname, log_q, qtype=_DNS_TYPE_AAAA)
    if udp_aaaa is not None:
        ip, ttl = udp_aaaa
        _cache_put(hostname, ip, ttl)
        log_q.put(("INFO", f"Resolved {hostname} via public UDP DNS (IPv6) -> {ip}"))
        return ip

    log_q.put(("WARNING",
               f"Public DNS unavailable for {hostname}  -> system DNS"))

    # 4) Last resort — system resolver. getaddrinfo also sees AAAA, so
    #    AAAA-only hosts still resolve here.
    info = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    for fam, _t, _p, _c, sa in info:
        if fam == socket.AF_INET:
            return sa[0]
    for fam, _t, _p, _c, sa in info:
        if fam == socket.AF_INET6:
            return sa[0]
    raise socket.gaierror(f"no usable address for {hostname}")


def connect_remote(host, port, use_doh, log_q):
    ip = resolve_doh(host, use_doh, log_q)
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(CONNECT_TIMEOUT)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect((ip, port))
        sock.settimeout(None)
    except Exception:
        try: sock.close()
        except OSError: pass
        raise
    return sock


def send_fragmented(sock, data, frag):
    if frag < 1:
        frag = 1
    off = 0
    n = len(data)
    while off < n:
        end = min(off + frag, n)
        chunk_off = off
        while chunk_off < end:
            sent = sock.send(data[chunk_off:end])
            if sent == 0:
                raise OSError("socket closed during fragmented send")
            chunk_off += sent
        off = end


def is_client_hello(d):
    return len(d) > 5 and d[0] == 0x16 and d[1] == 0x03 and d[5] == 0x01


def relay(a, b):
    def pump(s, d):
        try:
            while True:
                c = s.recv(BUFFER)
                if not c: break
                d.sendall(c)
        except OSError:
            pass
        finally:
            try: d.shutdown(socket.SHUT_WR)
            except OSError: pass

    t1 = threading.Thread(target=pump, args=(a, b), daemon=True)
    t2 = threading.Thread(target=pump, args=(b, a), daemon=True)
    t1.start(); t2.start(); t1.join(); t2.join()


def handle_connect(client, host, port, use_doh, frag, log_q):
    remote = None
    try:
        try:
            remote = connect_remote(host, port, use_doh, log_q)
        except Exception as e:
            log_q.put(("ERROR", f"Could not connect to {host}:{port} -> {e}"))
            try: client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except OSError: pass
            return
        try:
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        except OSError:
            return
        try:
            first = client.recv(BUFFER)
        except OSError:
            return
        if not first:
            return
        try:
            if is_client_hello(first):
                log_q.put(("INFO", f"[frag {frag}B]  {host}:{port}"))
                send_fragmented(remote, first, frag)
            else:
                remote.sendall(first)
        except OSError as e:
            log_q.put(("DEBUG", f"initial send failed for {host}:{port}: {e}"))
            return
        relay(client, remote)
    finally:
        if remote is not None:
            try: remote.close()
            except OSError: pass


def _strip_hop_by_hop(headers_block):
    if not headers_block.endswith(b"\r\n\r\n"):
        return headers_block
    body_split = headers_block[:-4]
    out = []
    for line in body_split.split(b"\r\n"):
        name, sep, _ = line.partition(b":")
        if sep and name.strip().lower() in _HOP_BY_HOP:
            continue
        out.append(line)
    return b"\r\n".join(out) + b"\r\n\r\n"


def handle_http(client, method, url, headers, use_doh, log_q):
    s = url[7:] if url.startswith("http://") else url
    ps = s.find("/")
    hp   = s[:ps] if ps != -1 else s
    path = s[ps:] if ps != -1 else "/"
    if ":" in hp:
        host, port_s = hp.rsplit(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            log_q.put(("ERROR", f"Bad port in URL: {url[:80]}"))
            return
    else:
        host, port = hp, 80

    remote = None
    try:
        remote = connect_remote(host, port, use_doh, log_q)
        remote.sendall(f"{method} {path} HTTP/1.1\r\n".encode() + _strip_hop_by_hop(headers))
        relay(client, remote)
    except Exception as e:
        log_q.put(("ERROR", f"HTTP relay error: {e}"))
    finally:
        if remote is not None:
            try: remote.close()
            except OSError: pass


def handle_client(client, use_doh, frag, log_q):
    try:
        raw = b""
        while b"\r\n\r\n" not in raw:
            c = client.recv(BUFFER)
            if not c: return
            raw += c
            if len(raw) > 65536: return
        hb, _, body = raw.partition(b"\r\n\r\n")
        lines = hb.split(b"\r\n")
        parts = lines[0].decode(errors="replace").split(" ", 2)
        if len(parts) < 2: return
        method, url = parts[0], parts[1]
        rh = b"\r\n".join(lines[1:]) + b"\r\n\r\n"
        if method.upper() == "CONNECT":
            if ":" in url:
                host, port_s = url.rsplit(":", 1)
                try:
                    port = int(port_s)
                except ValueError:
                    return
            else:
                host, port = url, 443
            log_q.put(("INFO", f"CONNECT  {host}:{port}"))
            handle_connect(client, host, port, use_doh, frag, log_q)
        else:
            log_q.put(("INFO", f"{method}  {url[:80]}"))
            handle_http(client, method, url, rh + body, use_doh, log_q)
    except Exception as e:
        log_q.put(("DEBUG", f"handle_client: {e}"))
    finally:
        try: client.close()
        except OSError: pass


# ─────────────────────────────────────────────────────────────────────────────
#  Windows proxy management (UNCHANGED)
# ─────────────────────────────────────────────────────────────────────────────
_IE = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def _refresh():
    if not _IS_WINDOWS:
        return
    try:
        w = ctypes.windll.wininet
        w.InternetSetOptionW(0, 39, 0, 0); w.InternetSetOptionW(0, 37, 0, 0)
    except Exception:
        pass


def proxy_enable(addr):
    if not _IS_WINDOWS:
        return None, None
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE, 0,
                           winreg.KEY_READ | winreg.KEY_WRITE)
        try:
            try:
                old_e = winreg.QueryValueEx(k, "ProxyEnable")[0]
            except FileNotFoundError:
                old_e = 0
            try:
                old_s = winreg.QueryValueEx(k, "ProxyServer")[0]
            except FileNotFoundError:
                old_s = ""
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, addr)
        finally:
            winreg.CloseKey(k)
        _refresh()
        return old_e, old_s
    except Exception:
        return None, None


def proxy_restore(old_e, old_s):
    if not _IS_WINDOWS:
        return
    if old_e is None:
        return
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE, 0, winreg.KEY_WRITE)
        try:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, int(old_e))
            winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, old_s or "")
        finally:
            winreg.CloseKey(k)
        _refresh()
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
#  Proxy server thread (UNCHANGED)
# ─────────────────────────────────────────────────────────────────────────────
class ProxyServer:
    def __init__(self):
        self._sock    = None
        self._stop    = threading.Event()
        self._thread  = None
        self._old_e   = None
        self._old_s   = None
        self._lock    = threading.Lock()
        self.log_q    = queue.Queue()

    def start(self, port, frag, use_doh):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
                sock.listen(256)
                sock.settimeout(1.0)
            except Exception:
                try: sock.close()
                except OSError: pass
                raise

            old_e, old_s = proxy_enable(f"127.0.0.1:{port}")
            self._sock = sock
            self._old_e, self._old_s = old_e, old_s
            self._stop.clear()
            self.log_q.put(("INFO",
                f"Proxy started on 127.0.0.1:{port}  |  fragment={frag}B  "
                f"|  DoH={'on' if use_doh else 'off'}"))
            self._thread = threading.Thread(target=self._run, args=(frag, use_doh),
                                            daemon=True)
            self._thread.start()

    def stop(self):
        with self._lock:
            if not self._thread:
                return
            self._stop.set()
            if self._sock:
                try: self._sock.close()
                except OSError: pass
            thread = self._thread
            old_e, old_s = self._old_e, self._old_s
            self._thread = None
            self._sock = None
            self._old_e = self._old_s = None

        if thread:
            thread.join(timeout=3)
        proxy_restore(old_e, old_s)
        self.log_q.put(("INFO", "Proxy stopped. Windows proxy restored."))

    def _run(self, frag, use_doh):
        sock = self._sock
        while not self._stop.is_set():
            try:
                client, _ = sock.accept()
                threading.Thread(target=handle_client,
                                 args=(client, use_doh, frag, self.log_q),
                                 daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop.is_set():
                    self.log_q.put(("ERROR", "Accept error — proxy stopped unexpectedly."))
                break

    @property
    def running(self):
        return bool(self._thread and self._thread.is_alive())


# ─────────────────────────────────────────────────────────────────────────────
#  System tray icon (Win32 Shell_NotifyIcon — pure ctypes)
# ─────────────────────────────────────────────────────────────────────────────
if _IS_WINDOWS:
    from ctypes import wintypes

    _user32   = ctypes.windll.user32
    _shell32  = ctypes.windll.shell32
    _kernel32 = ctypes.windll.kernel32

    _WM_DESTROY      = 0x0002
    _WM_COMMAND      = 0x0111
    _WM_LBUTTONUP    = 0x0202
    _WM_LBUTTONDBLCLK= 0x0203
    _WM_RBUTTONUP    = 0x0205
    _WM_USER         = 0x0400
    _WM_TRAY_CB      = _WM_USER + 1

    _NIM_ADD    = 0x00000000
    _NIM_MODIFY = 0x00000001
    _NIM_DELETE = 0x00000002
    _NIF_MESSAGE= 0x00000001
    _NIF_ICON   = 0x00000002
    _NIF_TIP    = 0x00000004

    _IDI_APPLICATION = 32512
    _IDC_ARROW       = 32512

    _HWND_MESSAGE = wintypes.HWND(-3)

    _TPM_RIGHTBUTTON = 0x0002
    _TPM_RETURNCMD   = 0x0100
    _TPM_NONOTIFY    = 0x0080

    _MF_STRING    = 0x00000000
    _MF_SEPARATOR = 0x00000800

    # WPARAM / LPARAM / LRESULT are pointer-sized in the real Win32 ABI.
    # Python's wintypes defines them as 32-bit, which corrupts arguments on
    # x64. Use pointer-sized types instead.
    _WPARAM  = ctypes.c_size_t
    _LPARAM  = ctypes.c_ssize_t
    _LRESULT = ctypes.c_ssize_t
    _UINT_PTR= ctypes.c_size_t

    _WNDPROC = ctypes.WINFUNCTYPE(
        _LRESULT,
        wintypes.HWND, wintypes.UINT, _WPARAM, _LPARAM,
    )

    class _WNDCLASSW(ctypes.Structure):
        _fields_ = [
            ("style",         wintypes.UINT),
            ("lpfnWndProc",   _WNDPROC),
            ("cbClsExtra",    ctypes.c_int),
            ("cbWndExtra",    ctypes.c_int),
            ("hInstance",     wintypes.HINSTANCE),
            ("hIcon",         wintypes.HICON),
            ("hCursor",       wintypes.HANDLE),
            ("hbrBackground", wintypes.HBRUSH),
            ("lpszMenuName",  wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
        ]

    class _POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

    class _MSG(ctypes.Structure):
        _fields_ = [
            ("hwnd",    wintypes.HWND),
            ("message", wintypes.UINT),
            ("wParam",  _WPARAM),
            ("lParam",  _LPARAM),
            ("time",    wintypes.DWORD),
            ("pt",      _POINT),
        ]

    class _NOTIFYICONDATAW(ctypes.Structure):
        _fields_ = [
            ("cbSize",          wintypes.DWORD),
            ("hWnd",            wintypes.HWND),
            ("uID",             wintypes.UINT),
            ("uFlags",          wintypes.UINT),
            ("uCallbackMessage",wintypes.UINT),
            ("hIcon",           wintypes.HICON),
            ("szTip",           wintypes.WCHAR * 128),
            ("dwState",         wintypes.DWORD),
            ("dwStateMask",     wintypes.DWORD),
            ("szInfo",          wintypes.WCHAR * 256),
            ("uVersion",        wintypes.DWORD),
            ("szInfoTitle",     wintypes.WCHAR * 64),
            ("dwInfoFlags",     wintypes.DWORD),
            ("guidItem",        ctypes.c_byte * 16),
            ("hBalloonIcon",    wintypes.HICON),
        ]

    # Bind argtypes/restype for everything we call. Without this, ctypes
    # passes ints as 32-bit c_int, which truncates pointers / handles on x64.
    _user32.DefWindowProcW.argtypes = [
        wintypes.HWND, wintypes.UINT, _WPARAM, _LPARAM,
    ]
    _user32.DefWindowProcW.restype  = _LRESULT

    _user32.GetMessageW.argtypes = [
        ctypes.POINTER(_MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT,
    ]
    _user32.GetMessageW.restype  = ctypes.c_int

    _user32.TranslateMessage.argtypes  = [ctypes.POINTER(_MSG)]
    _user32.TranslateMessage.restype   = wintypes.BOOL
    _user32.DispatchMessageW.argtypes  = [ctypes.POINTER(_MSG)]
    _user32.DispatchMessageW.restype   = _LRESULT

    _user32.PostMessageW.argtypes = [
        wintypes.HWND, wintypes.UINT, _WPARAM, _LPARAM,
    ]
    _user32.PostMessageW.restype  = wintypes.BOOL

    _user32.PostQuitMessage.argtypes = [ctypes.c_int]
    _user32.PostQuitMessage.restype  = None

    _user32.LoadIconW.argtypes   = [wintypes.HINSTANCE, wintypes.LPCWSTR]
    _user32.LoadIconW.restype    = wintypes.HICON
    _user32.LoadCursorW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
    _user32.LoadCursorW.restype  = wintypes.HANDLE

    _user32.RegisterClassW.argtypes = [ctypes.POINTER(_WNDCLASSW)]
    _user32.RegisterClassW.restype  = wintypes.ATOM

    _user32.CreateWindowExW.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
    ]
    _user32.CreateWindowExW.restype = wintypes.HWND

    _user32.CreatePopupMenu.argtypes = []
    _user32.CreatePopupMenu.restype  = wintypes.HMENU
    _user32.AppendMenuW.argtypes = [
        wintypes.HMENU, wintypes.UINT, _UINT_PTR, wintypes.LPCWSTR,
    ]
    _user32.AppendMenuW.restype  = wintypes.BOOL
    _user32.TrackPopupMenu.argtypes = [
        wintypes.HMENU, wintypes.UINT,
        ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, ctypes.c_void_p,
    ]
    _user32.TrackPopupMenu.restype  = wintypes.BOOL
    _user32.DestroyMenu.argtypes = [wintypes.HMENU]
    _user32.DestroyMenu.restype  = wintypes.BOOL
    _user32.GetCursorPos.argtypes = [ctypes.POINTER(_POINT)]
    _user32.GetCursorPos.restype  = wintypes.BOOL
    _user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    _user32.SetForegroundWindow.restype  = wintypes.BOOL

    _shell32.Shell_NotifyIconW.argtypes = [
        wintypes.DWORD, ctypes.POINTER(_NOTIFYICONDATAW),
    ]
    _shell32.Shell_NotifyIconW.restype  = wintypes.BOOL

    _kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    _kernel32.GetModuleHandleW.restype  = wintypes.HMODULE

    def _MAKEINTRESOURCE(i):
        # Win32 stock IDs are passed as LPCWSTR with the pointer value being
        # the small integer. ctypes won't auto-convert int→LPCWSTR; cast it.
        return ctypes.cast(ctypes.c_void_p(i), wintypes.LPCWSTR)


class TrayIcon:
    """
    Minimal Windows system-tray icon driven by Shell_NotifyIcon.

    A dedicated thread owns a hidden message-only window and pumps messages.
    Tray events are forwarded to the supplied callbacks via tk_after, which
    must marshal the call back onto the Tk main thread (use root.after(0, ...)).
    """

    _MENU_SHOW   = 1001
    _MENU_TOGGLE = 1002
    _MENU_EXIT   = 1003

    def __init__(self, on_show, on_toggle, on_exit, is_running, tk_after,
                 tooltip="DPI Bypass Proxy"):
        self.on_show    = on_show
        self.on_toggle  = on_toggle
        self.on_exit    = on_exit
        self.is_running = is_running   # callable -> bool, queried at menu open
        self.tk_after   = tk_after
        self.tooltip    = tooltip

        self._hwnd        = None
        self._wndproc_ref = None  # keep WNDPROC alive
        self._cls_name    = f"DPIBypassTray_{id(self)}"
        self._thread      = None
        self._added       = False
        self._ready       = threading.Event()
        self._supported   = _IS_WINDOWS

    def start(self):
        if not self._supported:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=2.0)

    def stop(self):
        if not self._supported or self._hwnd is None:
            return
        try:
            _user32.PostMessageW(self._hwnd, _WM_DESTROY, 0, 0)
        except Exception:
            pass

    # ── internals ────────────────────────────────────────────────────────────
    def _run(self):
        hinst = _kernel32.GetModuleHandleW(None)

        def _wndproc(hwnd, msg, wparam, lparam):
            if msg == _WM_TRAY_CB:
                evt = lparam & 0xFFFF
                if evt == _WM_LBUTTONUP or evt == _WM_LBUTTONDBLCLK:
                    self.tk_after(0, self.on_show)
                elif evt == _WM_RBUTTONUP:
                    self._show_menu(hwnd)
                return 0
            if msg == _WM_COMMAND:
                cmd = wparam & 0xFFFF
                if cmd == self._MENU_SHOW:
                    self.tk_after(0, self.on_show)
                elif cmd == self._MENU_TOGGLE:
                    self.tk_after(0, self.on_toggle)
                elif cmd == self._MENU_EXIT:
                    self.tk_after(0, self.on_exit)
                return 0
            if msg == _WM_DESTROY:
                self._remove_icon()
                _user32.PostQuitMessage(0)
                return 0
            return _user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        self._wndproc_ref = _WNDPROC(_wndproc)

        wc = _WNDCLASSW()
        wc.style         = 0
        wc.lpfnWndProc   = self._wndproc_ref
        wc.cbClsExtra    = 0
        wc.cbWndExtra    = 0
        wc.hInstance     = hinst
        wc.hIcon         = 0
        wc.hCursor       = _user32.LoadCursorW(None, _MAKEINTRESOURCE(_IDC_ARROW))
        wc.hbrBackground = 0
        wc.lpszMenuName  = None
        wc.lpszClassName = self._cls_name

        atom = _user32.RegisterClassW(ctypes.byref(wc))
        if not atom:
            self._ready.set()
            return

        hwnd = _user32.CreateWindowExW(
            0, self._cls_name, "DPIBypassTray",
            0, 0, 0, 0, 0,
            _HWND_MESSAGE, 0, hinst, None,
        )
        if not hwnd:
            self._ready.set()
            return

        self._hwnd = hwnd
        self._add_icon()
        self._ready.set()

        msg = _MSG()
        while _user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) > 0:
            _user32.TranslateMessage(ctypes.byref(msg))
            _user32.DispatchMessageW(ctypes.byref(msg))

    def _add_icon(self):
        nid = _NOTIFYICONDATAW()
        nid.cbSize           = ctypes.sizeof(_NOTIFYICONDATAW)
        nid.hWnd             = self._hwnd
        nid.uID              = 1
        nid.uFlags           = _NIF_MESSAGE | _NIF_ICON | _NIF_TIP
        nid.uCallbackMessage = _WM_TRAY_CB
        nid.hIcon            = _user32.LoadIconW(None, _MAKEINTRESOURCE(_IDI_APPLICATION))
        nid.szTip            = self.tooltip[:127]
        if _shell32.Shell_NotifyIconW(_NIM_ADD, ctypes.byref(nid)):
            self._added = True

    def _remove_icon(self):
        if not self._added:
            return
        nid = _NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
        nid.hWnd   = self._hwnd
        nid.uID    = 1
        _shell32.Shell_NotifyIconW(_NIM_DELETE, ctypes.byref(nid))
        self._added = False

    def _show_menu(self, hwnd):
        # Query the proxy state at menu-open time so the toggle item reflects
        # the current state instead of being a static "Stop proxy".
        try:
            running = bool(self.is_running())
        except Exception:
            running = False
        toggle_label = "Stop proxy" if running else "Start proxy"

        h_menu = _user32.CreatePopupMenu()
        _user32.AppendMenuW(h_menu, _MF_STRING, self._MENU_SHOW, "Open window")
        _user32.AppendMenuW(h_menu, _MF_STRING, self._MENU_TOGGLE, toggle_label)
        _user32.AppendMenuW(h_menu, _MF_SEPARATOR, 0, None)
        _user32.AppendMenuW(h_menu, _MF_STRING, self._MENU_EXIT, "Quit")

        pt = _POINT()
        _user32.GetCursorPos(ctypes.byref(pt))
        # Required so the menu vanishes when the user clicks elsewhere.
        _user32.SetForegroundWindow(hwnd)
        _user32.TrackPopupMenu(
            h_menu, _TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, None
        )
        _user32.PostMessageW(hwnd, 0x0000, 0, 0)  # WM_NULL — flushes
        _user32.DestroyMenu(h_menu)


# ─────────────────────────────────────────────────────────────────────────────
#  Friendly log formatter — translates raw proxy events into readable lines
#  for normal (non-verbose) mode. Verbose mode shows the original messages.
# ─────────────────────────────────────────────────────────────────────────────
_RX_STARTED = re.compile(
    r"^Proxy started on 127\.0\.0\.1:(?P<port>\d+)\s+\|\s+fragment=(?P<frag>\d+)B\s+\|\s+DoH=(?P<doh>on|off)$"
)
_RX_CONNECT = re.compile(r"^CONNECT\s+(?P<host>[^\s:]+):(?P<port>\d+)$")
_RX_FRAG    = re.compile(r"^\[frag\s+\d+B\]\s+(?P<host>[^\s:]+):(?P<port>\d+)$")
_RX_HTTP    = re.compile(r"^(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(?P<url>\S+)")
_RX_DOH_FAIL    = re.compile(r"^All DoH servers failed \((?P<host>[^)]+)\):.*->\s+trying public UDP DNS$")
_RX_UDP_OK      = re.compile(r"^Resolved (?P<host>\S+) via public UDP DNS -> (?P<ip>\S+)$")
_RX_V6_DOH_OK   = re.compile(r"^Resolved (?P<host>\S+) via DoH \(IPv6\) -> (?P<ip>\S+)$")
_RX_V6_UDP_OK   = re.compile(r"^Resolved (?P<host>\S+) via public UDP DNS \(IPv6\) -> (?P<ip>\S+)$")
_RX_UDP_FAIL    = re.compile(r"^Public DNS unavailable for (?P<host>\S+)\s+->\s+system DNS$")
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

    m = _RX_V6_DOH_OK.match(msg)
    if m:
        return ("OK", f"Resolved {m['host']} via IPv6  ({m['ip']})")

    m = _RX_V6_UDP_OK.match(msg)
    if m:
        return ("OK", f"Resolved {m['host']} via IPv6 public DNS  ({m['ip']})")

    m = _RX_UDP_FAIL.match(msg)
    if m:
        return ("WARNING", f"Public DNS unreachable for {m['host']} — using system DNS")

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


# ─────────────────────────────────────────────────────────────────────────────
#  GUI
# ─────────────────────────────────────────────────────────────────────────────

# Refined dark palette — slightly cooler base, more contrast between layers.
C = {
    "bg":         "#0e1116",
    "surface":    "#161b22",
    "surface2":   "#1c232c",
    "border":     "#262d36",
    "border_hi":  "#3a4350",
    "accent":     "#5b8dee",
    "accent_hov": "#7aa3f5",
    "ok":         "#3ecf8e",
    "ok_hov":     "#52d99c",
    "danger":     "#e05c5c",
    "danger_hov": "#eb7575",
    "warn":       "#e0a84a",
    "text":       "#e6e8ee",
    "text_dim":   "#a8aebb",
    "muted":      "#6c7383",
    "entry_bg":   "#0b0e13",
}

FONT_UI    = ("Segoe UI", 10)
FONT_UI_B  = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI Semibold", 14)
FONT_SUB   = ("Segoe UI", 9)
FONT_TINY  = ("Segoe UI", 8)
FONT_MONO  = ("Cascadia Mono", 9)
FONT_LOG   = ("Cascadia Mono", 9)


TOOLTIPS = {
    "port": (
        "Port the proxy listens on.\n\n"
        "Default: 8881. Change only if another application is already using this port.\n"
        "If you get a 'port already in use' error, try 8882 or any free port above 1024."
    ),
    "fragment": (
        "Size of each TCP fragment sent during TLS handshake (bytes).\n\n"
        "Default: 2. Smaller = harder for DPI to reassemble the SNI.\n"
        "If connections are refused or reset, try 1.\n"
        "If performance is slow on non-blocked sites, try 4 or 8."
    ),
    "no_doh": (
        "Disable DNS-over-HTTPS and use the system DNS instead.\n\n"
        "Default: off (DoH is active). Keep DoH on — it bypasses DNS poisoning.\n"
        "If DoH fails on your network, the proxy automatically falls back to\n"
        "plain UDP DNS aimed at public resolvers before touching system DNS.\n"
        "Enable this only if you specifically want to use system DNS."
    ),
    "verbose": (
        "Show all internal events including DEBUG messages and per-fragment notices.\n\n"
        "Default: off. The log stays concise and user-friendly.\n"
        "Enable when troubleshooting a specific issue — output becomes very detailed."
    ),
}


class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text   = text
        self.tw     = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _=None):
        x = self.widget.winfo_rootx() + 22
        y = self.widget.winfo_rooty() + 22
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        self.tw.configure(bg=C["border_hi"])
        inner = tk.Frame(self.tw, bg=C["surface2"], padx=12, pady=10)
        inner.pack(padx=1, pady=1)
        tk.Label(inner, text=self.text, justify="left", font=FONT_SUB,
                 bg=C["surface2"], fg=C["text"], wraplength=340).pack()

    def _hide(self, _=None):
        if self.tw:
            self.tw.destroy(); self.tw = None


class HoverButton(tk.Button):
    """tk.Button with a flat look and a colour-shift hover effect."""
    def __init__(self, master, *, bg, fg, hover_bg, **kw):
        super().__init__(master,
                         bg=bg, fg=fg,
                         activebackground=hover_bg, activeforeground=fg,
                         relief="flat", bd=0, cursor="hand2", **kw)
        self._bg, self._hover = bg, hover_bg
        self.bind("<Enter>", lambda _e: self.config(bg=self._hover))
        self.bind("<Leave>", lambda _e: self.config(bg=self._bg))

    def set_bg(self, bg, hover):
        self._bg, self._hover = bg, hover
        self.config(bg=bg, activebackground=hover)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DPI Bypass Proxy")
        self.configure(bg=C["bg"])
        self.minsize(640, 540)
        self.geometry("760x640")
        self.resizable(True, True)

        # tkinter scaling — pairs with SetProcessDpiAwareness for crisp text.
        try:
            dpi = self.winfo_fpixels("1i")  # pixels per inch at this monitor
            self.tk.call("tk", "scaling", dpi / 72.0)
        except Exception:
            pass

        self._init_style()

        self.proxy = ProxyServer()
        self._tray = TrayIcon(
            on_show=self._tray_show,
            on_toggle=self._tray_toggle,
            on_exit=self._tray_exit,
            is_running=lambda: self.proxy.running,
            tk_after=self.after,
            tooltip="DPI Bypass Proxy",
        )

        self._build()
        self._poll_log()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        atexit.register(self._ensure_stop)
        if _IS_WINDOWS:
            self._install_console_handler()

        self._tray.start()

    # ── ttk styling ──────────────────────────────────────────────────────────
    def _init_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".",
                        background=C["bg"], foreground=C["text"],
                        fieldbackground=C["entry_bg"], font=FONT_UI)

        # Entry — flat with a subtle bottom-line accent on focus.
        style.configure("Modern.TEntry",
                        fieldbackground=C["entry_bg"],
                        foreground=C["text"],
                        insertcolor=C["text"],
                        bordercolor=C["border"],
                        lightcolor=C["border"],
                        darkcolor=C["border"],
                        relief="flat", padding=6)
        style.map("Modern.TEntry",
                  bordercolor=[("focus", C["accent"])],
                  lightcolor=[("focus", C["accent"])],
                  darkcolor=[("focus", C["accent"])])

        # Checkbutton — blends with bg, accent on indicator.
        style.configure("Modern.TCheckbutton",
                        background=C["bg"], foreground=C["text"],
                        focuscolor=C["bg"], padding=2)
        style.map("Modern.TCheckbutton",
                  background=[("active", C["bg"])],
                  foreground=[("active", C["accent_hov"])])

        # Vertical scrollbar for the log.
        style.configure("Modern.Vertical.TScrollbar",
                        background=C["surface"],
                        troughcolor=C["bg"],
                        bordercolor=C["bg"],
                        arrowcolor=C["text_dim"],
                        gripcount=0, relief="flat")
        style.map("Modern.Vertical.TScrollbar",
                  background=[("active", C["surface2"])])

    # ── Console handler (preserve restore-on-kill behaviour) ─────────────────
    def _install_console_handler(self):
        def handler(event):
            try:
                if self.proxy.running:
                    self.proxy.stop()
            except Exception:
                pass
            return False
        self._console_handler_routine = ctypes.WINFUNCTYPE(
            ctypes.c_bool, ctypes.c_uint
        )(handler)
        try:
            ctypes.windll.kernel32.SetConsoleCtrlHandler(
                self._console_handler_routine, True
            )
        except Exception:
            pass

    # ── Layout ───────────────────────────────────────────────────────────────
    def _build(self):
        # Root grid:
        #   row 0  header
        #   row 1  separator
        #   row 2  settings
        #   row 3  separator
        #   row 4  action bar (start/stop, hide-to-tray, status)
        #   row 5  log header
        #   row 6  log  (expands)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(6, weight=1)

        # ── Header ──────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=C["surface"])
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_columnconfigure(0, weight=1)
        inner_h = tk.Frame(hdr, bg=C["surface"])
        inner_h.grid(row=0, column=0, padx=22, pady=(16, 14), sticky="w")
        tk.Label(inner_h, text="DPI Bypass Proxy",
                 font=FONT_TITLE, bg=C["surface"], fg=C["text"]
                 ).grid(row=0, column=0, sticky="w")
        tk.Label(inner_h,
                 text="Runs in user-space  ·  no admin required  ·  zero dependencies",
                 font=FONT_SUB, bg=C["surface"], fg=C["muted"]
                 ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        tk.Frame(self, bg=C["border"], height=1).grid(row=1, column=0, sticky="ew")

        # ── Settings card ───────────────────────────────────────────────────
        panel = tk.Frame(self, bg=C["bg"])
        panel.grid(row=2, column=0, sticky="ew", padx=22, pady=(18, 10))
        panel.grid_columnconfigure(1, weight=1)

        tk.Label(panel, text="SETTINGS", font=FONT_UI_B,
                 bg=C["bg"], fg=C["muted"]
                 ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))

        self._port_var    = tk.IntVar(value=8881)
        self._frag_var    = tk.IntVar(value=2)
        self._nodoh_var   = tk.BooleanVar(value=False)
        self._verbose_var = tk.BooleanVar(value=False)

        cfg = [
            ("port",     "Port",            self._port_var,    "int"),
            ("fragment", "Fragment size",   self._frag_var,    "int"),
            ("no_doh",   "Disable DoH",     self._nodoh_var,   "bool"),
            ("verbose",  "Verbose logging", self._verbose_var, "bool"),
        ]
        self._rows = []
        for i, (key, label, var, kind) in enumerate(cfg, start=1):
            row = tk.Frame(panel, bg=C["bg"])
            row.grid(row=i, column=0, columnspan=3, sticky="ew", pady=4)
            row.grid_columnconfigure(2, weight=1)

            info = tk.Label(row, text="?", font=FONT_TINY,
                            bg=C["border"], fg=C["text_dim"],
                            width=2, cursor="question_arrow",
                            relief="flat", padx=4, pady=2)
            info.grid(row=0, column=0, padx=(0, 10))
            Tooltip(info, TOOLTIPS[key])

            tk.Label(row, text=label, font=FONT_UI,
                     bg=C["bg"], fg=C["text"], anchor="w"
                     ).grid(row=0, column=1, sticky="w")

            if kind == "int":
                ent = ttk.Entry(row, textvariable=var, width=10,
                                style="Modern.TEntry", font=FONT_UI)
                ent.grid(row=0, column=2, sticky="w")
                self._rows.append(ent)
            else:
                chk = ttk.Checkbutton(row, variable=var,
                                      style="Modern.TCheckbutton")
                chk.grid(row=0, column=2, sticky="w")
                self._rows.append(chk)

        tk.Frame(self, bg=C["border"], height=1
                 ).grid(row=3, column=0, sticky="ew", padx=22)

        # ── Action bar (Start/Stop, Hide-to-tray, status pill) ──────────────
        actions = tk.Frame(self, bg=C["bg"])
        actions.grid(row=4, column=0, sticky="ew")
        actions.grid_columnconfigure(0, weight=1)

        bar = tk.Frame(actions, bg=C["bg"], pady=16)
        bar.grid(row=0, column=0)

        self._btn = HoverButton(
            bar, text="▶  Start",
            bg=C["ok"], fg=C["bg"], hover_bg=C["ok_hov"],
            font=FONT_UI_B, padx=30, pady=10,
            command=self._toggle,
        )
        self._btn.grid(row=0, column=0, padx=(0, 10))

        self._tray_btn = HoverButton(
            bar, text="Hide to tray",
            bg=C["surface2"], fg=C["text_dim"], hover_bg=C["border"],
            font=FONT_UI, padx=16, pady=10,
            command=self._hide_to_tray,
        )
        self._tray_btn.grid(row=0, column=1, padx=(0, 14))

        # Status pill: dot + label, side by side.
        status_wrap = tk.Frame(bar, bg=C["bg"])
        status_wrap.grid(row=0, column=2, padx=(6, 0))
        self._status_dot = tk.Label(status_wrap, text="●",
                                    font=("Segoe UI", 13),
                                    bg=C["bg"], fg=C["danger"])
        self._status_dot.grid(row=0, column=0, padx=(0, 6))
        self._status_text = tk.Label(status_wrap, text="Stopped",
                                     font=FONT_UI,
                                     bg=C["bg"], fg=C["text_dim"])
        self._status_text.grid(row=0, column=1)

        # ── Log header ──────────────────────────────────────────────────────
        log_hdr = tk.Frame(self, bg=C["bg"])
        log_hdr.grid(row=5, column=0, sticky="ew", padx=22, pady=(2, 6))
        log_hdr.grid_columnconfigure(1, weight=1)
        tk.Label(log_hdr, text="ACTIVITY", font=FONT_UI_B,
                 bg=C["bg"], fg=C["muted"]
                 ).grid(row=0, column=0, sticky="w")
        HoverButton(log_hdr, text="Clear",
                    bg=C["surface2"], fg=C["text_dim"], hover_bg=C["border"],
                    font=FONT_SUB, padx=12, pady=4,
                    command=self._clear_log
                    ).grid(row=0, column=2, sticky="e")

        # ── Log area (expands) ──────────────────────────────────────────────
        log_wrap = tk.Frame(self, bg=C["border"])
        log_wrap.grid(row=6, column=0, sticky="nsew", padx=22, pady=(0, 18))
        log_wrap.grid_rowconfigure(0, weight=1)
        log_wrap.grid_columnconfigure(0, weight=1)

        self._log = scrolledtext.ScrolledText(
            log_wrap,
            font=FONT_LOG,
            bg=C["surface"], fg=C["text"],
            insertbackground=C["text"],
            relief="flat", bd=0,
            state="disabled", wrap="word",
            padx=12, pady=10,
        )
        self._log.grid(row=0, column=0, sticky="nsew", padx=1, pady=1)

        # Tag colours — used by both modes.
        self._log.tag_config("ts",      foreground=C["muted"])
        self._log.tag_config("INFO",    foreground=C["text"])
        self._log.tag_config("OK",      foreground=C["ok"])
        self._log.tag_config("CONN",    foreground=C["accent"])
        self._log.tag_config("WARNING", foreground=C["warn"])
        self._log.tag_config("ERROR",   foreground=C["danger"])
        self._log.tag_config("DEBUG",   foreground=C["muted"])
        self._log.tag_config("level",   foreground=C["text_dim"])

    # ── Toggle proxy ─────────────────────────────────────────────────────────
    def _toggle(self):
        if self.proxy.running:
            self._btn.config(state="disabled")
            threading.Thread(target=self._do_stop, daemon=True).start()
        else:
            self._start()

    def _start(self):
        try:
            port = int(self._port_var.get())
            frag = int(self._frag_var.get())
        except (tk.TclError, ValueError):
            self._append_friendly("ERROR", "Port and fragment size must be integers.")
            return
        if not (1 <= port <= 65535):
            self._append_friendly("ERROR", "Port must be between 1 and 65535.")
            return
        if not (1 <= frag <= 512):
            self._append_friendly("ERROR", "Fragment size must be between 1 and 512.")
            return

        try:
            self.proxy.start(port, frag, not self._nodoh_var.get())
        except OSError as e:
            self._append_friendly("ERROR", f"Could not start proxy: {e}")
            return
        except Exception as e:
            self._append_friendly("ERROR", f"Unexpected error starting proxy: {e}")
            return

        for w in self._rows:
            w.config(state="disabled")
        self._btn.config(text="■  Stop")
        self._btn.set_bg(C["danger"], C["danger_hov"])
        self._status_dot.config(fg=C["ok"])
        self._status_text.config(text="Running", fg=C["ok"])

    def _do_stop(self):
        try:
            self.proxy.stop()
        except Exception as e:
            self.proxy.log_q.put(("ERROR", f"Error during stop: {e}"))
        self.after(0, self._after_stop)

    def _after_stop(self):
        for w in self._rows:
            w.config(state="normal")
        self._btn.config(text="▶  Start", state="normal")
        self._btn.set_bg(C["ok"], C["ok_hov"])
        self._status_dot.config(fg=C["danger"])
        self._status_text.config(text="Stopped", fg=C["text_dim"])

    # ── Tray actions ─────────────────────────────────────────────────────────
    def _hide_to_tray(self):
        try:
            self.withdraw()
        except tk.TclError:
            pass

    def _tray_show(self):
        try:
            self.deiconify()
            self.lift()
            self.focus_force()
        except tk.TclError:
            pass

    def _tray_toggle(self):
        # Reuse the same path as the in-window button so the UI state, the
        # status pill, and the entry-disabling stay in sync regardless of
        # whether the user clicked the button or the tray menu.
        self._toggle()

    def _tray_exit(self):
        self._on_close()

    # ── Log helpers ──────────────────────────────────────────────────────────
    def _poll_log(self):
        verbose = self._verbose_var.get()
        try:
            while True:
                level, msg = self.proxy.log_q.get_nowait()
                if verbose:
                    self._append_raw(level, msg)
                else:
                    formatted = friendly_format(level, msg)
                    if formatted is None:
                        continue
                    self._append_friendly(*formatted)
        except queue.Empty:
            pass
        self.after(120, self._poll_log)

    def _append_raw(self, level, msg):
        ts = time.strftime("%H:%M:%S")
        self._log.config(state="normal")
        self._log.insert("end", f"{ts}  ", "ts")
        tag = level if level in ("INFO", "WARNING", "ERROR", "DEBUG") else "INFO"
        self._log.insert("end", f"{level:<7}  ", "level")
        self._log.insert("end", f"{msg}\n", tag)
        self._log.see("end")
        self._log.config(state="disabled")

    def _append_friendly(self, level, msg):
        ts = time.strftime("%H:%M:%S")
        self._log.config(state="normal")
        self._log.insert("end", f"{ts}   ", "ts")
        tag = level if level in self._log.tag_names() else "INFO"
        self._log.insert("end", f"{msg}\n", tag)
        self._log.see("end")
        self._log.config(state="disabled")

    def _clear_log(self):
        self._log.config(state="normal")
        self._log.delete("1.0", "end")
        self._log.config(state="disabled")

    # ── Shutdown ─────────────────────────────────────────────────────────────
    def _ensure_stop(self):
        try:
            if self.proxy.running:
                self.proxy.stop()
        except Exception:
            pass
        try:
            self._tray.stop()
        except Exception:
            pass

    def _on_close(self):
        if self.proxy.running:
            self._btn.config(state="disabled")
            threading.Thread(target=self._shutdown_and_close, daemon=True).start()
        else:
            self._tray.stop()
            self.destroy()

    def _shutdown_and_close(self):
        try:
            self.proxy.stop()
        except Exception:
            pass
        self.after(0, self._final_destroy)

    def _final_destroy(self):
        try:
            self._tray.stop()
        except Exception:
            pass
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.mainloop()
