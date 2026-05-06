#!/usr/bin/env python3
"""
dpi_bypass_gui.py — GUI front-end for the DPI bypass proxy.
All proxy logic is embedded; no separate file needed.
Requires only Python standard library (tkinter included).
"""

import tkinter as tk
from tkinter import scrolledtext, font as tkfont
import threading
import socket
import urllib.request
import urllib.parse
import json
import ssl
import time
import re
import logging
import queue
import ctypes
import winreg
import atexit
import sys

# ─────────────────────────────────────────────────────────────────────────────
#  Proxy core (same logic as dpi_bypass.py)
# ─────────────────────────────────────────────────────────────────────────────

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
def _is_ip(h): return bool(_IP_RE.match(h))
_no_proxy_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

BUFFER          = 32768
CONNECT_TIMEOUT = 10
DOH_SERVERS = [
    "https://1.1.1.1/dns-query",
    "https://1.0.0.1/dns-query",
    "https://8.8.8.8/dns-query",
    "https://9.9.9.9/dns-query",
]

_dns_cache: dict = {}
_dns_lock = threading.Lock()

def resolve_doh(hostname, use_doh, log_q):
    if _is_ip(hostname): return hostname
    if not use_doh:       return socket.gethostbyname(hostname)
    with _dns_lock:
        if hostname in _dns_cache:
            ip, exp = _dns_cache[hostname]
            if time.time() < exp: return ip
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    last_err = None
    for srv in DOH_SERVERS:
        try:
            url = f"{srv}?name={urllib.parse.quote(hostname)}&type=A"
            req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
            with _no_proxy_opener.open(req, timeout=4) as r:
                data = json.loads(r.read())
            ans = [a["data"] for a in data.get("Answer",[]) if a.get("type")==1]
            if not ans: continue
            ip  = ans[0]
            ttl = data["Answer"][0].get("TTL", 60)
            with _dns_lock: _dns_cache[hostname] = (ip, time.time()+ttl)
            return ip
        except Exception as e: last_err = e
    log_q.put(("WARNING", f"All DoH servers failed ({hostname}): {last_err}  -> system DNS"))
    return socket.gethostbyname(hostname)

def connect_remote(host, port, use_doh, log_q):
    ip   = resolve_doh(host, use_doh, log_q)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.connect((ip, port))
    sock.settimeout(None)
    return sock

def send_fragmented(sock, data, frag):
    off = 0
    while off < len(data):
        sock.send(data[off:off+frag]); off += frag

def is_client_hello(d): return len(d)>5 and d[0]==0x16 and d[1]==0x03

def relay(a, b):
    def pump(s, d):
        try:
            while True:
                c = s.recv(BUFFER)
                if not c: break
                d.sendall(c)
        except OSError: pass
        finally:
            for x in (s, d):
                try: x.shutdown(socket.SHUT_WR)
                except OSError: pass
    t1 = threading.Thread(target=pump, args=(a,b), daemon=True)
    t2 = threading.Thread(target=pump, args=(b,a), daemon=True)
    t1.start(); t2.start(); t1.join(); t2.join()

def handle_connect(client, host, port, use_doh, frag, log_q):
    try: remote = connect_remote(host, port, use_doh, log_q)
    except Exception as e:
        log_q.put(("ERROR", f"Could not connect to {host}:{port} -> {e}"))
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); client.close(); return
    client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    try:    first = client.recv(BUFFER)
    except OSError: client.close(); remote.close(); return
    if not first: client.close(); remote.close(); return
    if is_client_hello(first):
        log_q.put(("INFO", f"[frag {frag}B]  {host}:{port}"))
        send_fragmented(remote, first, frag)
    else: remote.sendall(first)
    relay(client, remote)

def handle_http(client, method, url, headers, use_doh, log_q):
    s = url[7:] if url.startswith("http://") else url
    ps = s.find("/")
    hp   = s[:ps] if ps!=-1 else s
    path = s[ps:] if ps!=-1 else "/"
    if ":" in hp: host, port = hp.rsplit(":",1); port=int(port)
    else:         host, port = hp, 80
    try:
        remote = connect_remote(host, port, use_doh, log_q)
        remote.sendall(f"{method} {path} HTTP/1.1\r\n".encode() + headers)
        relay(client, remote)
    except Exception as e:
        log_q.put(("ERROR", f"HTTP relay error: {e}")); client.close()

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
            if ":" in url: host, port = url.rsplit(":",1); port=int(port)
            else:           host, port = url, 443
            log_q.put(("INFO", f"CONNECT  {host}:{port}"))
            handle_connect(client, host, port, use_doh, frag, log_q)
        else:
            log_q.put(("INFO", f"{method}  {url[:80]}"))
            handle_http(client, method, url, rh+body, use_doh, log_q)
    except Exception as e: log_q.put(("DEBUG", f"handle_client: {e}"))
    finally:
        try: client.close()
        except OSError: pass

# ─────────────────────────────────────────────────────────────────────────────
#  Windows proxy management
# ─────────────────────────────────────────────────────────────────────────────
_IE = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

def _refresh():
    try:
        w = ctypes.windll.wininet
        w.InternetSetOptionW(0,39,0,0); w.InternetSetOptionW(0,37,0,0)
    except Exception: pass

def proxy_enable(addr):
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE, 0, winreg.KEY_READ|winreg.KEY_WRITE)
        try:    old_e = winreg.QueryValueEx(k,"ProxyEnable")[0]; old_s = winreg.QueryValueEx(k,"ProxyServer")[0]
        except: old_e, old_s = 0, ""
        winreg.SetValueEx(k,"ProxyEnable",0,winreg.REG_DWORD,1)
        winreg.SetValueEx(k,"ProxyServer",0,winreg.REG_SZ,addr)
        winreg.CloseKey(k); _refresh()
        return old_e, old_s
    except: return None, None

def proxy_restore(old_e, old_s):
    if old_e is None: return
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(k,"ProxyEnable",0,winreg.REG_DWORD,old_e)
        if old_s: winreg.SetValueEx(k,"ProxyServer",0,winreg.REG_SZ,old_s)
        winreg.CloseKey(k); _refresh()
    except: pass

# ─────────────────────────────────────────────────────────────────────────────
#  Proxy server thread
# ─────────────────────────────────────────────────────────────────────────────
class ProxyServer:
    def __init__(self):
        self._sock    = None
        self._stop    = threading.Event()
        self._thread  = None
        self._old_e   = None
        self._old_s   = None
        self.log_q    = queue.Queue()

    def start(self, port, frag, use_doh):
        if self._thread and self._thread.is_alive(): return
        self._stop.clear()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(256)
        self._sock.settimeout(1.0)
        self._old_e, self._old_s = proxy_enable(f"127.0.0.1:{port}")
        self.log_q.put(("INFO", f"Proxy started on 127.0.0.1:{port}  |  fragment={frag}B  |  DoH={'on' if use_doh else 'off'}"))
        self._thread = threading.Thread(target=self._run, args=(frag, use_doh), daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._sock:
            try: self._sock.close()
            except: pass
        if self._thread: self._thread.join(timeout=3)
        proxy_restore(self._old_e, self._old_s)
        self._old_e = self._old_s = None
        self.log_q.put(("INFO", "Proxy stopped. Windows proxy restored."))

    def _run(self, frag, use_doh):
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
                threading.Thread(target=handle_client,
                                 args=(client, use_doh, frag, self.log_q),
                                 daemon=True).start()
            except socket.timeout: continue
            except OSError:
                if not self._stop.is_set():
                    self.log_q.put(("ERROR", "Accept error — proxy stopped unexpectedly."))
                break

    @property
    def running(self): return bool(self._thread and self._thread.is_alive())

# ─────────────────────────────────────────────────────────────────────────────
#  GUI
# ─────────────────────────────────────────────────────────────────────────────

C = {
    "bg":        "#0f0f13",
    "surface":   "#1a1a24",
    "border":    "#2a2a3a",
    "accent":    "#5b8dee",
    "accent2":   "#3ecf8e",
    "danger":    "#e05c5c",
    "warn":      "#e0a84a",
    "text":      "#e2e2ee",
    "muted":     "#6b6b88",
    "entry_bg":  "#12121a",
}

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
        "Enable this only if DoH itself is causing timeouts and system DNS works fine."
    ),
    "verbose": (
        "Show all debug-level messages in the log panel.\n\n"
        "Default: off. Enable when troubleshooting — the log becomes very detailed.\n"
        "Turn off during normal use to keep the log readable."
    ),
}

class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text   = text
        self.tw     = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _=None):
        x = self.widget.winfo_rootx() + 24
        y = self.widget.winfo_rooty() + 24
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        self.tw.configure(bg=C["border"])
        inner = tk.Frame(self.tw, bg=C["surface"], padx=12, pady=10)
        inner.pack(padx=1, pady=1)
        tk.Label(inner, text=self.text, justify="left", font=("Consolas",9),
                 bg=C["surface"], fg=C["text"], wraplength=320).pack()

    def hide(self, _=None):
        if self.tw:
            self.tw.destroy(); self.tw = None

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DPI Bypass Proxy")
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self.proxy = ProxyServer()
        self._build()
        self._poll_log()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        atexit.register(self._ensure_stop)

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build(self):
        # ── Header
        hdr = tk.Frame(self, bg=C["surface"], pady=14)
        hdr.pack(fill="x")
        tk.Label(hdr, text="DPI BYPASS PROXY", font=("Consolas",14,"bold"),
                 bg=C["surface"], fg=C["accent"]).pack()
        tk.Label(hdr, text="ARM64 compatible  ·  pure Python  ·  zero dependencies",
                 font=("Consolas",8), bg=C["surface"], fg=C["muted"]).pack()

        sep = tk.Frame(self, bg=C["border"], height=1)
        sep.pack(fill="x")

        # ── Settings panel
        panel = tk.Frame(self, bg=C["bg"], padx=20, pady=16)
        panel.pack(fill="x")

        tk.Label(panel, text="SETTINGS", font=("Consolas",8,"bold"),
                 bg=C["bg"], fg=C["muted"]).grid(row=0, column=0, columnspan=3,
                 sticky="w", pady=(0,10))

        self._port_var    = tk.IntVar(value=8881)
        self._frag_var    = tk.IntVar(value=2)
        self._nodoh_var   = tk.BooleanVar(value=False)
        self._verbose_var = tk.BooleanVar(value=False)

        self._rows = []
        cfg = [
            ("port",    "Port",              self._port_var,    "int"),
            ("fragment","Fragment size",      self._frag_var,    "int"),
            ("no_doh",  "Disable DoH",       self._nodoh_var,   "bool"),
            ("verbose", "Verbose logging",   self._verbose_var, "bool"),
        ]
        for i, (key, label, var, kind) in enumerate(cfg, start=1):
            row_frame = tk.Frame(panel, bg=C["bg"])
            row_frame.grid(row=i, column=0, columnspan=3, sticky="ew", pady=3)

            info_btn = tk.Label(row_frame, text="?", font=("Consolas",8,"bold"),
                                bg=C["border"], fg=C["muted"],
                                width=2, cursor="question_arrow",
                                relief="flat", padx=4, pady=2)
            info_btn.pack(side="left", padx=(0,8))
            Tooltip(info_btn, TOOLTIPS[key])

            tk.Label(row_frame, text=label, font=("Consolas",10),
                     bg=C["bg"], fg=C["text"], width=16,
                     anchor="w").pack(side="left")

            if kind == "int":
                ent = tk.Entry(row_frame, textvariable=var, width=8,
                               font=("Consolas",10),
                               bg=C["entry_bg"], fg=C["text"],
                               insertbackground=C["text"],
                               relief="flat", bd=0,
                               highlightthickness=1,
                               highlightcolor=C["accent"],
                               highlightbackground=C["border"])
                ent.pack(side="left", ipady=4)
                self._rows.append(ent)
            else:
                chk = tk.Checkbutton(row_frame, variable=var,
                                     bg=C["bg"], fg=C["text"],
                                     activebackground=C["bg"],
                                     activeforeground=C["accent"],
                                     selectcolor=C["entry_bg"],
                                     relief="flat", bd=0,
                                     cursor="hand2")
                chk.pack(side="left")
                self._rows.append(chk)

        sep2 = tk.Frame(self, bg=C["border"], height=1)
        sep2.pack(fill="x", padx=20)

        # ── Start / Stop button
        btn_frame = tk.Frame(self, bg=C["bg"], pady=14)
        btn_frame.pack()
        self._btn = tk.Button(btn_frame, text="▶  START",
                              font=("Consolas",11,"bold"),
                              bg=C["accent2"], fg=C["bg"],
                              activebackground="#2fa872",
                              activeforeground=C["bg"],
                              relief="flat", bd=0, padx=28, pady=8,
                              cursor="hand2",
                              command=self._toggle)
        self._btn.pack()

        self._status = tk.Label(btn_frame, text="● STOPPED",
                                font=("Consolas",9), bg=C["bg"], fg=C["danger"])
        self._status.pack(pady=(6,0))

        sep3 = tk.Frame(self, bg=C["border"], height=1)
        sep3.pack(fill="x", padx=20)

        # ── Log panel
        log_hdr = tk.Frame(self, bg=C["bg"], padx=20, pady=10)
        log_hdr.pack(fill="x")
        tk.Label(log_hdr, text="LOG", font=("Consolas",8,"bold"),
                 bg=C["bg"], fg=C["muted"]).pack(side="left")
        tk.Button(log_hdr, text="Clear", font=("Consolas",8),
                  bg=C["border"], fg=C["muted"],
                  activebackground=C["surface"], activeforeground=C["text"],
                  relief="flat", bd=0, padx=8, pady=2,
                  cursor="hand2",
                  command=self._clear_log).pack(side="right")

        self._log = scrolledtext.ScrolledText(
            self, width=68, height=18,
            font=("Consolas",9),
            bg=C["surface"], fg=C["text"],
            insertbackground=C["text"],
            relief="flat", bd=0,
            state="disabled",
            wrap="word",
            padx=10, pady=8,
        )
        self._log.pack(padx=20, pady=(0,16))

        # Tag colours
        self._log.tag_config("INFO",    foreground=C["text"])
        self._log.tag_config("WARNING", foreground=C["warn"])
        self._log.tag_config("ERROR",   foreground=C["danger"])
        self._log.tag_config("DEBUG",   foreground=C["muted"])
        self._log.tag_config("ts",      foreground=C["muted"])

    # ── Toggle proxy ──────────────────────────────────────────────────────────
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
            assert 1 <= port <= 65535, "Port must be 1–65535"
            assert 1 <= frag <= 512,   "Fragment must be 1–512"
        except Exception as e:
            self._append("ERROR", f"Invalid settings: {e}")
            return
        for w in self._rows: w.config(state="disabled")
        self.proxy.start(port, frag, not self._nodoh_var.get())
        self._btn.config(text="■  STOP", bg=C["danger"],
                         activebackground="#c04444")
        self._status.config(text="● RUNNING", fg=C["accent2"])

    def _do_stop(self):
        self.proxy.stop()
        self.after(0, self._after_stop)

    def _after_stop(self):
        for w in self._rows: w.config(state="normal")
        self._btn.config(text="▶  START", bg=C["accent2"],
                         activebackground="#2fa872", state="normal")
        self._status.config(text="● STOPPED", fg=C["danger"])

    # ── Log helpers ───────────────────────────────────────────────────────────
    def _poll_log(self):
        verbose = self._verbose_var.get()
        try:
            while True:
                level, msg = self.proxy.log_q.get_nowait()
                if level == "DEBUG" and not verbose: continue
                self._append(level, msg)
        except queue.Empty: pass
        self.after(120, self._poll_log)

    def _append(self, level, msg):
        ts = time.strftime("%H:%M:%S")
        self._log.config(state="normal")
        self._log.insert("end", f"{ts}  ", "ts")
        self._log.insert("end", f"{level:<7}  {msg}\n", level)
        self._log.see("end")
        self._log.config(state="disabled")

    def _clear_log(self):
        self._log.config(state="normal")
        self._log.delete("1.0", "end")
        self._log.config(state="disabled")

    # ── Shutdown ──────────────────────────────────────────────────────────────
    def _ensure_stop(self):
        if self.proxy.running: self.proxy.stop()

    def _on_close(self):
        if self.proxy.running:
            threading.Thread(target=self._shutdown_and_close, daemon=True).start()
        else:
            self.destroy()

    def _shutdown_and_close(self):
        self.proxy.stop()
        self.after(0, self.destroy)


if __name__ == "__main__":
    app = App()
    app.mainloop()
