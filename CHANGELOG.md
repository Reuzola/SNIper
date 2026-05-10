# Changelog

## v1.1.0 — 2026-05-10

### Distribution

Python no longer needs to be installed. Running `build_exe.bat` produces a
single `.exe` that bundles the Python runtime via PyInstaller. ARM64 and x64
each require their own build on a native machine — PyInstaller does not
cross-compile.

The `.bat` launchers and `error_log.txt` have been removed; they are replaced
by `build_exe.bat` and the EXE itself.

### System tray icon

When minimized, the app disappears from the taskbar and moves to the system
tray. The Win32 `Shell_NotifyIcon` API is called directly via `ctypes`, so no
third-party packages are needed. Right-clicking the tray icon shows a small
context menu whose contents change based on proxy state.

### GUI

Widgets were migrated to `ttk` with a custom style built on the `clam` theme.
The window no longer appears blurry on High-DPI displays; `SetProcessDpiAwareness`
is called before any Tk window is created (Per-Monitor v2, v1, and System DPI
Aware are tried in order depending on the OS version).

### DNS cache

Switched from `dict` to `OrderedDict`. The cache is now capped at 1024
entries; when the limit is reached the oldest entry is evicted. TTL expiry
logic was extracted into dedicated `_cache_get` / `_cache_put` functions.
Frequently accessed domains stay in cache longer because each successful
lookup moves the entry to the end of the order.

### DoH reliability

A `User-Agent` header is now sent alongside `Accept` in DoH requests. The
ALPN protocol is explicitly set to `http/1.1` — without it some Python builds
send no ALPN at all and the server assumes HTTP/2, responding with `505`. The
SSL context is created once at module load instead of per request. TTL values
are clamped to a minimum of 30 seconds. When a DoH request fails, the error
detail is now logged at `DEBUG` level.

### Proxy protocol

Hop-by-hop headers defined in RFC 7230 (`connection`, `keep-alive`,
`transfer-encoding`, etc.) are stripped from requests before forwarding. In
the previous version these headers were passed through as-is, which could
cause connection errors on some servers.

### Minor fixes

- `fragment_and_send` now clamps `frag` to 1 if a value below 1 is passed.
- If connecting the upstream socket fails, the socket is properly closed
  before the exception propagates.
- `winreg` import is wrapped in a try/except; if it fails `_IS_WINDOWS` is
  set to `False` so the module at least loads outside Windows.

---

## v1.0.0 — 2026-05-05

Initial release. Core features:

- TLS ClientHello fragmentation (2-byte segments via `TCP_NODELAY`)
- DNS-over-HTTPS (Cloudflare and Google, TTL-aware in-memory cache)
- Command-line interface via `dpi_bypass.py`
- tkinter-based GUI via `dpi_bypass_gui.py`
- Automatic Windows system proxy management via `HKCU` registry key
