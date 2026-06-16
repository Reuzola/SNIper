"""Per-connection handling: connect to the remote, fragment the ClientHello,
relay bytes, and parse the HTTP/CONNECT request line.

Logic is unchanged from the original embedded proxy core; only the platform
flag and shared constants now come from sniper.compat / sniper.config, and
name resolution from sniper.dns.
"""
from __future__ import annotations

import socket
import threading

from sniper.compat import IS_WINDOWS
from sniper.config import BUFFER, CONNECT_TIMEOUT, _HOP_BY_HOP
from sniper.dns import resolve_doh


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


def handle_http(client, method, url, headers, use_doh, log_q):
    s = url[7:] if url.startswith("http://") else url
    ps = s.find("/")
    hp   = s[:ps] if ps != -1 else s
    path = s[ps:] if ps != -1 else "/"
    parsed = _split_host_port(hp, 80)
    if parsed is None:
        log_q.put(("ERROR", f"Bad port in URL: {url[:80]}"))
        return
    host, port = parsed

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
            parsed = _split_host_port(url, 443)
            if parsed is None:
                return
            host, port = parsed
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
