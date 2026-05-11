# Changelog

## v1.1.1 — 2026-05-11

### DNS resolution chain — survives blocked DoH and IPv6-only hosts

The resolver previously had a two-step chain (DoH → system DNS) which broke
under two real-world conditions surfaced by user testing on a third x64
machine:

1. **DoH endpoints unreachable.** On networks where the ISP or local
   middleware blocks TLS to `1.1.1.1`, `8.8.8.8`, etc., every DoH server
   failed and the resolver fell back to the system resolver — which is the
   exact resolver DoH was meant to bypass. Domains under DNS poisoning
   (e.g. `discord.com`) then returned a poisoned address and connections
   could not be established.
2. **IPv6-only hosts.** `ipv6.msftconnecttest.com` (Windows's IPv6
   connectivity probe) publishes only an AAAA record. The resolver asked
   only for A records, so DoH and system DNS both returned "no record" and
   the HTTP relay logged a spurious error.

The chain is now: **DoH-A → public UDP DNS A → DoH-AAAA → public UDP DNS
AAAA → `getaddrinfo`**. IPv4 is preferred whenever available; IPv6 is used
only when no A record exists anywhere.

### Plain UDP DNS fallback

When all DoH servers fail, the resolver now sends plain DNS queries over
UDP/53 to public resolvers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `1.0.0.1`,
`8.8.4.4`, `208.67.222.222`). Most ISP-level DPI only poisons responses
from the ISP's own resolver and passes UDP/53 traffic to other IPs
through untouched, so this fallback recovers connectivity even when DoH
is blocked. The DNS packet builder and parser are hand-rolled per
RFC 1035 — no new dependencies.

### AAAA (IPv6) record support

`_udp_dns_query` and `_parse_dns_response` accept a query-type parameter
(A or AAAA). The DoH path was factored into a `_doh_lookup` helper so it
can run twice (once for each record type) without duplicating the request
loop. `connect_remote` inspects the resolved address and opens an
`AF_INET6` socket when given an IPv6 literal, so IPv6-only hosts are
reachable on dual-stack machines.

### System-DNS fallback uses `getaddrinfo`

The final fallback was `socket.gethostbyname`, which is IPv4-only. It is
now `socket.getaddrinfo` with `SOCK_STREAM`, which returns both families.
IPv4 is preferred when both exist; IPv6 is used only as a last resort.
This change also matters when `--no-doh` is set — AAAA-only hosts now
resolve correctly through the system resolver too.

### GUI activity log

New friendly-formatted lines for the additional resolution paths:

- `Secure DNS unavailable for X — trying public DNS` (DoH failed,
  attempting plain UDP next).
- `Resolved X via public DNS  (IP)` (plain UDP DNS succeeded).
- `Resolved X via IPv6  (IP)` (AAAA via DoH succeeded).
- `Resolved X via IPv6 public DNS  (IP)` (AAAA via plain UDP succeeded).
- `Public DNS unreachable for X — using system DNS` (both DoH and plain
  UDP exhausted across all record types).

The `Disable DoH` tooltip was updated to mention that turning DoH off
also disables the plain UDP fallback.

---

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
