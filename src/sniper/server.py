"""ProxyServer thread: the accept loop, concurrency cap, and start/stop that
toggles the Windows system proxy.

Whatever ends a session, the system proxy is put back through the one restore
mechanism, winproxy.proxy_restore(): Stop and window close call stop(), which
always restores; an accept loop that dies on its own fails safe (closes the
port, restores, tells the UI); and Windows sign-out / restart / shutdown is
handled by session_ending(), which the session watcher calls synchronously
before Windows terminates the process.
"""
from __future__ import annotations

import errno
import socket
import threading
import queue
import time

from sniper.compat import IS_WINDOWS
from sniper.config import MAX_CONNECTIONS
from sniper.proxy import handle_client
from sniper.winproxy import (
    proxy_enable, proxy_restore, recover_orphaned_proxy, _proxy_gpo_locked,
)

# accept() errors that are about one incoming connection or a momentary
# resource shortage, not about the listening socket: a client that reset or
# aborted before it was accepted, an interrupted call, or running out of
# descriptors / buffers for a moment. Winsock documents all of these for
# accept(). Windows socket errors carry the WSA code in errno and winerror.
_TRANSIENT_WSA = frozenset({
    10004,  # WSAEINTR
    10024,  # WSAEMFILE
    10035,  # WSAEWOULDBLOCK
    10053,  # WSAECONNABORTED
    10054,  # WSAECONNRESET
    10055,  # WSAENOBUFS
})
_TRANSIENT_ERRNO = frozenset(
    getattr(errno, name) for name in (
        "EINTR", "EMFILE", "ENFILE", "ENOBUFS",
        "ECONNABORTED", "ECONNRESET", "EAGAIN", "EWOULDBLOCK")
    if hasattr(errno, name))

# How long transient errors may follow one another, with no successful accept
# and no quiet timeout in between, before the loop treats them as fatal. A
# condition that never clears (say, the process is out of descriptors for
# good) must still end in the fail-safe rather than a proxy that silently
# accepts nothing.
_TRANSIENT_FAILURE_BUDGET = 30.0
_TRANSIENT_BACKOFF = 0.05   # seconds between retries during such a run

# How long a session-end hook waits for _sys_lock before going ahead anyway.
# The lock is only ever held for a few registry operations; the bound just
# guarantees the session watcher's window procedure can never hang on it.
_SESSION_LOCK_TIMEOUT = 5.0

_MSG_STOPPED = "Proxy stopped. Windows proxy restored."
_MSG_KEPT = "Proxy server stopped; your manual proxy change was left in place."


def _err_code(exc):
    code = getattr(exc, "winerror", None)
    return code if code is not None else getattr(exc, "errno", None)


def _is_transient_accept_error(exc):
    """True if an accept() error only concerns one connection or a passing
    shortage, so the loop should keep serving."""
    err = getattr(exc, "errno", None)
    return (getattr(exc, "winerror", None) in _TRANSIENT_WSA
            or err in _TRANSIENT_WSA or err in _TRANSIENT_ERRNO)


class ProxyServer:
    def __init__(self):
        self._sock    = None
        self._stop    = threading.Event()
        self._thread  = None
        self._lock    = threading.Lock()
        self.log_q    = queue.Queue()
        self.port     = None
        self.addr     = None
        # Serializes every change to the system proxy made on behalf of this
        # server (apply, restore, and the flags below) across the UI, accept
        # and session-watcher threads, so a re-apply can never land after the
        # restore that ends a session. Re-entrant because
        # session_end_cancelled() calls _apply_system_proxy() while holding it.
        # Lock order: _lock before _sys_lock, never the other way round.
        self._sys_lock = threading.RLock()
        self._applied = False
        self._suspended_for_session_end = False
        # Set by the fail-safe; the UI collects it with take_unexpected_stop().
        self._unexpected_stop = threading.Event()

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
                # The port really bound: the requested one, or the one the OS
                # picked for port 0. This is what clients get pointed at.
                port = sock.getsockname()[1]
            except Exception:
                try: sock.close()
                except OSError: pass
                raise
            self.port = port
            self.addr = f"127.0.0.1:{port}"

            if _proxy_gpo_locked():
                self.log_q.put(("WARNING",
                    "Group Policy disables per-user proxy settings on this "
                    "machine — SNIper cannot change the system proxy here."))
            self._sock = sock
            self._stop.clear()
            # A fail-safe notice from an earlier session is stale now that a
            # new one starts; the UI must not flip this one to "Stopped".
            self._unexpected_stop.clear()
            thread = threading.Thread(target=self._run, args=(frag, use_doh),
                                      daemon=True)
            self._thread = thread
            try:
                # Serve the port first, so clients are never pointed at a port
                # nobody accepts on.
                thread.start()
                old_a = self._apply_system_proxy()
            except BaseException:
                self._abort_start(sock)
                raise
            self.log_q.put(("INFO",
                f"Proxy started on 127.0.0.1:{port}  |  fragment={frag}B  "
                f"|  DoH={'on' if use_doh else 'off'}"))
            if old_a:
                self.log_q.put(("WARNING",
                    "A PAC script (AutoConfigURL) was active; it has been "
                    "temporarily disabled and will be restored on stop."))

    def _abort_start(self, sock):
        """Undo a start() that failed after binding (called with _lock held):
        close the port and put back whatever part of the system proxy was
        already applied, so a failed Start never leaves either behind."""
        self._stop.set()
        try: sock.close()
        except OSError: pass
        self._sock = None
        self._thread = None
        with self._sys_lock:
            try:
                proxy_restore()
            except Exception:
                pass
            self._applied = False

    def _apply_system_proxy(self):
        """Point the Windows proxy at this session's address.

        Returns the genuine PAC URL that was temporarily disabled, or None.
        Every apply goes through here (Start, and the re-apply after a
        cancelled sign-out) so they are all serialized with the restores.
        """
        with self._sys_lock:
            # Records the genuine baseline durably before overwriting the live
            # values; returns the genuine PAC (or None).
            old_a = proxy_enable(self.addr)
            self._applied = True
            return old_a

    def stop(self):
        """End the session, if there is one, and always restore the system
        proxy. Idempotent: on a never-started or already-stopped server it is
        a cheap no-op restore that logs nothing."""
        with self._lock:
            thread = self._thread
            if thread is not None:
                self._stop.set()
                if self._sock:
                    try: self._sock.close()
                    except OSError: pass
                self._thread = None
                self._sock = None

        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=3)
        # Undo our own change from the durable baseline and clear it. If the
        # user changed the proxy while we ran, restore backs off and leaves it;
        # a clean stop leaves no residue for the next launch either way.
        with self._sys_lock:
            result = proxy_restore()
            self._applied = False
            self._suspended_for_session_end = False
        if result == "kept":
            self.log_q.put(("INFO", _MSG_KEPT))
        elif thread is not None or result == "restored":
            self.log_q.put(("INFO", _MSG_STOPPED))

    # ── Windows session end ──────────────────────────────────────────────────
    def session_ending(self):
        """Windows is signing out, restarting or shutting down.

        Called on the session watcher's thread, inside its window procedure,
        for WM_QUERYENDSESSION and WM_ENDSESSION(TRUE). The proxy is put back
        right here, synchronously: once WM_ENDSESSION returns, Windows may end
        the process at any moment. Always restores (cheap and idempotent), so
        a forced shutdown that skips WM_QUERYENDSESSION is covered too. The
        server threads keep running in case the user cancels. Never touches
        Tk and never raises.
        """
        try:
            acquired = self._sys_lock.acquire(timeout=_SESSION_LOCK_TIMEOUT)
            try:
                try:
                    proxy_restore()
                except Exception:
                    pass
                self._applied = False
                if self.has_session:
                    self._suspended_for_session_end = True
            finally:
                if acquired:
                    self._sys_lock.release()
        except Exception:
            pass

    def session_end_cancelled(self):
        """The sign-out / shutdown was cancelled (WM_ENDSESSION(FALSE)): point
        the system proxy at the still-running server again. Same thread rules
        as session_ending(); never raises."""
        try:
            if not self._sys_lock.acquire(timeout=_SESSION_LOCK_TIMEOUT):
                # Re-applying without the lock could race a Stop and leave the
                # proxy pointing at a closed port; leaving it off is the safe
                # side, and the user can press Start again.
                self._suspended_for_session_end = False
                self.log_q.put(("WARNING",
                    "Sign-out was cancelled, but the system proxy could not be "
                    "re-applied — press Stop, then Start."))
                return
            try:
                suspended = self._suspended_for_session_end
                self._suspended_for_session_end = False
                if suspended and self.running:
                    self._apply_system_proxy()
                    self.log_q.put(("INFO",
                        "Sign-out was cancelled — system proxy re-applied."))
            finally:
                self._sys_lock.release()
        except Exception:
            pass

    # ── Accept loop ──────────────────────────────────────────────────────────
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

        # When the current run of back-to-back transient errors began; None
        # while accept() is healthy.
        first_transient = None
        try:
            while not self._stop.is_set():
                try:
                    client, _ = sock.accept()
                except socket.timeout:
                    # A quiet second: nothing waiting and nothing failing, so
                    # any earlier transient trouble is over.
                    first_transient = None
                    continue
                except OSError as e:
                    if self._stop.is_set():
                        break  # stop() closed the socket: a normal end
                    if _is_transient_accept_error(e):
                        now = time.monotonic()
                        if first_transient is None:
                            first_transient = now
                        if now - first_transient < _TRANSIENT_FAILURE_BUDGET:
                            self.log_q.put(("DEBUG",
                                f"accept: transient error {_err_code(e)}, continuing"))
                            time.sleep(_TRANSIENT_BACKOFF)
                            continue
                    self._fail_safe(e, sock)
                    break
                first_transient = None
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
        except Exception as e:
            # Whatever else ends the loop must not strand the proxy either.
            if not self._stop.is_set():
                self._fail_safe(e, sock)

    def _fail_safe(self, exc, sock):
        """The accept loop died on its own: end the session the way Stop
        would, from the accept thread.

        Closes the listening socket so clients fail fast instead of hanging
        in its backlog, puts the system proxy back, and flags the UI to show
        "Stopped". It never calls stop(), which joins this very thread, and
        never raises. If the session is no longer the one this loop served
        (a Stop or a new Start got there first), they own the teardown and
        nothing is done here. _lock is held throughout, so a new Start waits
        until this session is fully torn down and restored.
        """
        try:
            with self._lock:
                if sock is None or self._sock is not sock:
                    return
                self.log_q.put(("ERROR", "Accept error — proxy stopped unexpectedly."))
                self.log_q.put(("DEBUG", f"accept loop ended by {exc!r}"))
                try: sock.close()
                except Exception: pass
                self._sock = None
                self._thread = None   # the session is over
                with self._sys_lock:
                    try:
                        result = proxy_restore()
                    except Exception:
                        result = None
                    self._applied = False
                    self._suspended_for_session_end = False
                if result == "restored":
                    self.log_q.put(("INFO",
                        "Windows proxy restored after the unexpected stop."))
                elif result == "kept":
                    self.log_q.put(("INFO", _MSG_KEPT))
                self._unexpected_stop.set()
        except Exception:
            pass

    def take_unexpected_stop(self):
        """True once after the fail-safe ended a session, then False again.
        Polled by the UI on its own thread."""
        if self._unexpected_stop.is_set():
            self._unexpected_stop.clear()
            return True
        return False

    @property
    def has_session(self):
        """True from Start until Stop or the fail-safe ends the session, even
        if the accept thread has already died: that is what Stop must undo."""
        return self._thread is not None

    @property
    def running(self):
        return bool(self._thread and self._thread.is_alive())
