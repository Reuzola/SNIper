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
from sniper.winproxy import (
    proxy_enable, proxy_restore, recover_orphaned_proxy, _proxy_gpo_locked,
)


class ProxyServer:
    def __init__(self):
        self._sock    = None
        self._stop    = threading.Event()
        self._thread  = None
        self._lock    = threading.Lock()
        self.log_q    = queue.Queue()

    def recover(self):
        """Self-heal a proxy left stranded by a previous ungraceful exit.

        Runs once at startup, before any new session, so merely opening the app
        undoes a proxy left behind by a prior force-kill / power-loss / shutdown.
        Footprint-gated: the genuine baseline is put back only when the live
        proxy is still exactly what SNIper applied; if the user changed it
        between the crash and this launch, that change is left in place. A clean
        state is a no-op and logs nothing (no false recovery).
        """
        try:
            result = recover_orphaned_proxy()
        except Exception:
            result = None
        if result == "restored":
            self.log_q.put(("INFO",
                "Recovered a proxy left by a previous unclean exit — "
                "Windows proxy restored."))
        elif result == "kept":
            self.log_q.put(("INFO",
                "A previous unclean exit was detected, but the proxy had since "
                "been changed manually — your change was left in place."))

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
            # Records the genuine baseline durably before overwriting the live
            # values; returns the genuine PAC (or None) for the note below.
            old_a = proxy_enable(f"127.0.0.1:{port}")
            self._sock = sock
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
            self._thread = None
            self._sock = None

        if thread:
            thread.join(timeout=3)
        # Undo our own change from the durable baseline and clear it. If the
        # user changed the proxy while we ran, restore backs off and leaves it;
        # a clean stop leaves no residue for the next launch either way.
        result = proxy_restore()
        if result == "kept":
            self.log_q.put(("INFO",
                "Proxy server stopped; your manual proxy change was left in place."))
        else:
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
