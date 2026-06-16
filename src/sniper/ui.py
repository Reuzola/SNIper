"""Tk App window: theme palette, fonts, tooltips, hover buttons, DPI
awareness and the window/tray wiring. Logic unchanged from the embedded
original; the platform flag, icon path, proxy server, tray icon and friendly
formatter now come from their dedicated modules.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import queue
import ctypes
import atexit

from sniper.compat import IS_WINDOWS
from sniper.resources import ICON_PATH
from sniper.server import ProxyServer
from sniper.tray import TrayIcon
from sniper.logformat import friendly_format

# shell32 handle for the taskbar-identity call below. The matching argtypes
# are bound once in sniper.tray (imported above); this is the same cached
# WinDLL, so the binding carries over.
if IS_WINDOWS:
    _shell32 = ctypes.windll.shell32


# ─────────────────────────────────────────────────────────────────────────────
#  High-DPI awareness — must run BEFORE any Tk window is created.
# ─────────────────────────────────────────────────────────────────────────────
def _enable_high_dpi():
    if not IS_WINDOWS:
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
# Monospaced font for the log panel. Cascadia Mono ships in-box only on
# Windows 11 (and on Windows 10 only when Windows Terminal was installed),
# so the real family is resolved at runtime by _resolve_mono_font() once a
# Tk root exists — see App.__init__. These values are placeholders.
FONT_MONO  = ("Cascadia Mono", 9)
FONT_LOG   = ("Cascadia Mono", 9)


def _resolve_mono_font():
    """Return the best monospaced family Tk can actually render.

    When a named family is missing Tk silently substitutes a proportional
    default, which looks wrong for a log panel. Checking the family list
    lets us fall back deliberately: Consolas (Vista+), then Lucida Console,
    then Courier New (universal). Needs an existing Tk root, so this runs
    from App.__init__, not at import time.
    """
    import tkinter.font as tkfont
    try:
        available = set(tkfont.families())
    except tk.TclError:
        return "Courier New"
    for family in ("Cascadia Mono", "Consolas", "Lucida Console", "Courier New"):
        if family in available:
            return family
    return "Courier New"


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


def _set_app_user_model_id():
    """Give the process an explicit taskbar identity.

    Without this, a frozen Python app can inherit a generic or
    interpreter-derived identity, which makes the taskbar button show the
    wrong icon. Tagging the process ties the taskbar button (and any
    pinned shortcut) to SNIper. Must run before the first window appears.
    """
    if not IS_WINDOWS:
        return
    try:
        _shell32.SetCurrentProcessExplicitAppUserModelID("SNIper.DPIBypassProxy")
    except (OSError, AttributeError):
        pass


def _apply_window_icon(win):
    """Give a Tk window the SNIper icon — title bar, Alt-Tab and taskbar.

    Uses iconbitmap(default=...) so every Toplevel opened afterwards picks
    up the same icon. Silently does nothing if the .ico cannot be found.
    """
    if not ICON_PATH:
        return
    try:
        win.iconbitmap(default=ICON_PATH)
    except Exception:
        pass


class App(tk.Tk):
    def __init__(self):
        _set_app_user_model_id()   # taskbar identity — before any window
        super().__init__()
        self.title("SNIper")
        _apply_window_icon(self)   # title bar, Alt-Tab and taskbar icon
        self.configure(bg=C["bg"])
        # Clamp the window to the screen. On small displays (1366×768 and
        # below), especially at >100% DPI scaling, the default 760×640 plus
        # window chrome can spill off-screen. Never request more than the
        # screen can show, and lower the minimum size to match so it cannot
        # override the clamp.
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        win_w = min(760, sw - 60)
        win_h = min(640, sh - 100)
        self.minsize(min(640, win_w), min(540, win_h))
        self.geometry(f"{win_w}x{win_h}")
        self.resizable(True, True)

        # tkinter scaling — pairs with SetProcessDpiAwareness for crisp text.
        try:
            dpi = self.winfo_fpixels("1i")  # pixels per inch at this monitor
            self.tk.call("tk", "scaling", dpi / 72.0)
        except Exception:
            pass

        # Resolve the monospaced font now that a Tk root exists — Cascadia
        # Mono is absent on stock Windows 10, so fall back gracefully.
        global FONT_MONO, FONT_LOG
        _mono = _resolve_mono_font()
        FONT_MONO = (_mono, 9)
        FONT_LOG  = (_mono, 9)

        self._init_style()

        self.proxy = ProxyServer()
        self._tray = TrayIcon(
            on_show=self._tray_show,
            on_toggle=self._tray_toggle,
            on_exit=self._tray_exit,
            is_running=lambda: self.proxy.running,
            tk_after=self.after,
            tooltip="SNIper",
        )

        self._build()
        self._poll_log()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        atexit.register(self._ensure_stop)
        if IS_WINDOWS:
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
        tk.Label(inner_h, text="SNIper",
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
