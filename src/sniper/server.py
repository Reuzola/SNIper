"""ProxyServer thread: the accept loop, concurrency cap, and start/stop that
toggles the Windows system proxy. Logic unchanged from the embedded original;
the platform flag, connection cap, request handler and Windows-proxy helpers
now come from their dedicated modules.
"""
from __future__ import annotations

import socket
import threading
import queue

from sniper.compat import IS_WINDOWS
from sniper.config import MAX_CONNECTIONS
from sniper.proxy import handle_client
from sniper.winproxy import proxy_enable, proxy_restore, _proxy_gpo_locked


class ProxyServer:
    def __init__(self):
        self._sock    = None
        self._stop    = threading.Event()
        self._thread  = None
        self._old_e   = None
        self._old_s   = None
        self._old_a   = None
        self._lock    = threading.Lock()
        self.log_q    = queue.Queue()

    def start(self, port, frag, use_doh):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # On Windows SO_REUSEADDR lets a different process bind the same
            # address and hijack connections; SO_EXCLUSIVEADDRUSE is the
            # correct exclusive bind. SO_REUSEADDR stays for other platforms.
            if IS_WINDOWS:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
                sock.listen(256)
                sock.settimeout(1.0)
            except Exception:
                try: sock.close()
                except OSError: pass
                raise

            if _proxy_gpo_locked():
                self.log_q.put(("WARNING",
                    "Group Policy disables per-user proxy settings on this "
                    "machine — SNIper cannot change the system proxy here."))
            old_e, old_s, old_a = proxy_enable(f"127.0.0.1:{port}")
            self._sock = sock
            self._old_e, self._old_s, self._old_a = old_e, old_s, old_a
            self._stop.clear()
            self.log_q.put(("INFO",
                f"Proxy started on 127.0.0.1:{port}  |  fragment={frag}B  "
                f"|  DoH={'on' if use_doh else 'off'}"))
            if old_a:
                self.log_q.put(("WARNING",
                    "A PAC script (AutoConfigURL) was active; it has been "
                    "temporarily disabled and will be restored on stop."))
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
            old_e, old_s, old_a = self._old_e, self._old_s, self._old_a
            self._thread = None
            self._sock = None
            self._old_e = self._old_s = self._old_a = None

        if thread:
            thread.join(timeout=3)
        proxy_restore(old_e, old_s, old_a)
        self.log_q.put(("INFO", "Proxy stopped. Windows proxy restored."))

    def _run(self, frag, use_doh):
        sock = self._sock
        # Cap concurrent handler threads so a connection burst can't exhaust
        # the OS thread limit and crash the accept loop; over the cap the
        # client is refused and simply retries once a slot frees.
        conn_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

        def _serve(client):
            try:
                handle_client(client, use_doh, frag, self.log_q)
            finally:
                conn_slots.release()

        while not self._stop.is_set():
            try:
                client, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop.is_set():
                    self.log_q.put(("ERROR", "Accept error — proxy stopped unexpectedly."))
                break
            if not conn_slots.acquire(blocking=False):
                self.log_q.put(("WARNING",
                    f"Connection limit ({MAX_CONNECTIONS}) reached — refusing a connection"))
                try: client.close()
                except OSError: pass
                continue
            try:
                threading.Thread(target=_serve, args=(client,), daemon=True).start()
            except RuntimeError:
                conn_slots.release()
                try: client.close()
                except OSError: pass

    @property
    def running(self):
        return bool(self._thread and self._thread.is_alive())
