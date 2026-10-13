"""Per-connection handling: connect to the remote, fragment the ClientHello,
relay bytes, and parse the HTTP/CONNECT request line.

Requests addressed to SNIper itself are answered here and never proxied. An
origin-form request (the URL is a bare path) is one made TO SNIper, not
through it: the safe-mode PAC script is served from its one-off path and
anything else gets a 404. A proxy request aimed back at SNIper's own port is
refused with 508 instead of connecting SNIper to itself.

The proxying logic is unchanged from the original embedded proxy core; only
the platform flag and shared constants now come from sniper.compat /
sniper.config, and name resolution from sniper.dns.
"""
from __future__ import annotations

import socket
import threading
from collections import namedtuple

from sniper.compat import IS_WINDOWS
from sniper.config import BUFFER, CONNECT_TIMEOUT, _HOP_BY_HOP
from sniper.dns import resolve_doh
from sniper.pac import PAC_CONTENT_TYPE

# What one session serves besides proxying: the port it listens on (for the
# self-loop guard) and, in safe mode, the PAC script's one-off path and its
# body as ASCII bytes. pac_path is None in Compatibility mode, where every
# request to SNIper itself gets a 404.
ServeConfig = namedtuple("ServeConfig", "listen_port pac_path pac_body")

# Target names that reach SNIper's own listening socket on 127.0.0.1.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})

_NOT_FOUND = (b"HTTP/1.1 404 Not Found\r\n"
              b"Content-Length: 0\r\nConnection: close\r\n\r\n")
_LOOP_DETECTED = (b"HTTP/1.1 508 Loop Detected\r\n"
                  b"Content-Length: 0\r\nConnection: close\r\n\r\n")


def _enable_keepalive(sock):
    """Turn on TCP keepalive on a remote socket.

    After connect() the socket is switched to blocking (settimeout(None)) and
    the relay loop sits in recv(). If the peer vanishes without a FIN/RST
    (laptop sleep, Wi-Fi change, NAT idle-timeout) that recv() blocks forever
    and leaks the handler plus its two relay threads. Keepalive lets the OS
    detect the dead peer so recv() raises and the threads unwind.
    """
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        return
    # Windows waits 2 hours before the first probe by default; shorten that
    # so a dead connection is reaped in ~1-2 minutes. SIO_KEEPALIVE_VALS
    # takes (onoff, idle_ms, interval_ms).
    if IS_WINDOWS:
        try:
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 60_000, 10_000))
        except (OSError, AttributeError, ValueError):
            pass


def connect_remote(host, port, use_doh, log_q):
    ip = resolve_doh(host, use_doh, log_q)
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(CONNECT_TIMEOUT)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect((ip, port))
        _enable_keepalive(sock)
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


def _split_host_port(authority, default_port):
    """Split a 'host:port' authority into (host, port), or None if malformed.

    A bracketed IPv6 literal ('[2001:db8::1]:443' or '[2001:db8::1]') has its
    brackets stripped so the bare address reaches the resolver, which rejects
    the bracketed form.
    """
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            return None
        host, tail = authority[1:end], authority[end + 1:]
        if not tail:
            return host, default_port
        if not tail.startswith(":"):
            return None
        port_s = tail[1:]
    elif ":" in authority:
        host, _, port_s = authority.rpartition(":")
    else:
        return authority, default_port
    try:
        return host, int(port_s)
    except ValueError:
        return None


def _http_target(url):
    """(host, port, path) of an absolute-form request URL such as
    'http://host:port/path', or None if its port is malformed."""
    s = url[7:] if url.startswith("http://") else url
    ps = s.find("/")
    hp   = s[:ps] if ps != -1 else s
    path = s[ps:] if ps != -1 else "/"
    parsed = _split_host_port(hp, 80)
    if parsed is None:
        return None
    return parsed[0], parsed[1], path


def handle_http(client, method, url, headers, use_doh, log_q):
    target = _http_target(url)
    if target is None:
        log_q.put(("ERROR", f"Bad port in URL: {url[:80]}"))
        return
    host, port, path = target

    remote = None
    try:
        try:
            remote = connect_remote(host, port, use_doh, log_q)
        except Exception as e:
            # Surface an unreachable/unresolvable target as a defined 502,
            # exactly as the CONNECT path does — never a silent client drop.
            # A connectivity probe (Windows NCSI) made through the proxy then
            # reaches the same verdict a direct connection would: on an
            # IPv4-only host an IPv6-only target fails cleanly here instead of
            # collapsing the machine's connectivity state to "offline".
            log_q.put(("ERROR", f"Could not connect to {host}:{port} -> {e}"))
            try: client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except OSError: pass
            return
        try:
            remote.sendall(f"{method} {path} HTTP/1.1\r\n".encode() + _strip_hop_by_hop(headers))
        except OSError as e:
            log_q.put(("DEBUG", f"initial send failed for {host}:{port}: {e}"))
            return
        relay(client, remote)
    finally:
        if remote is not None:
            try: remote.close()
            except OSError: pass


def _serve_local(client, method, url, serve, log_q):
    """Answer an origin-form request, one made to SNIper itself: the PAC
    script for GET/HEAD on this session's script path (the query string is
    ignored), 404 for anything else. Logged at DEBUG only, so a client
    fetching the script never shows up as a connection in the friendly log."""
    path = url.split("?", 1)[0]
    pac_path = serve.pac_path if serve is not None else None
    if pac_path is not None and path == pac_path and method in ("GET", "HEAD"):
        body = serve.pac_body
        head = ("HTTP/1.1 200 OK\r\n"
                f"Content-Type: {PAC_CONTENT_TYPE}\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Cache-Control: no-store, max-age=0\r\n"
                "Connection: close\r\n\r\n").encode("ascii")
        client.sendall(head + body if method == "GET" else head)
        log_q.put(("DEBUG", f"PAC script served ({method})"))
    else:
        client.sendall(_NOT_FOUND)
        log_q.put(("DEBUG", f"Not found: {method} {url[:80]}"))


def _is_own_port(host, port, serve):
    """True if host:port is SNIper's own listening socket. Proxying such a
    request would only connect SNIper to itself, eating a connection slot
    per hop. Other loopback ports are proxied as usual."""
    return (serve is not None and port == serve.listen_port
            and host.lower() in _LOOPBACK_HOSTS)


def _refuse_loop(client, log_q):
    log_q.put(("WARNING", "Refused a request to SNIper's own port (loop)."))
    try: client.sendall(_LOOP_DETECTED)
    except OSError: pass


def handle_client(client, use_doh, frag, log_q, serve=None):
    """Serve one client connection. serve is the session's ServeConfig; with
    None nothing is served locally and no port counts as SNIper's own."""
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
        if url.startswith("/"):
            # Origin-form: a request to SNIper, never one to proxy. (Passed
            # on, it would try to resolve an empty host.)
            _serve_local(client, method, url, serve, log_q)
        elif method.upper() == "CONNECT":
            parsed = _split_host_port(url, 443)
            if parsed is None:
                return
            host, port = parsed
            if _is_own_port(host, port, serve):
                _refuse_loop(client, log_q)
                return
            log_q.put(("INFO", f"CONNECT  {host}:{port}"))
            handle_connect(client, host, port, use_doh, frag, log_q)
        else:
            target = _http_target(url)
            if target is not None and _is_own_port(target[0], target[1], serve):
                _refuse_loop(client, log_q)
                return
            log_q.put(("INFO", f"{method}  {url[:80]}"))
            handle_http(client, method, url, rh + body, use_doh, log_q)
    except Exception as e:
        log_q.put(("DEBUG", f"handle_client: {e}"))
    finally:
        try: client.close()
        except OSError: pass
