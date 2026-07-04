# Changelog

## v1.1.6 - 2026-07-04

A transport-correctness release. On a host with no usable IPv6 route, a name
that publishes only an AAAA record was resolved to its sole IPv6 address, and
the outbound connect then failed with `WSAENETUNREACH` (WinError 10051). On the
plain-HTTP relay path that failure surfaced as a silent drop of the client
connection with no response at all. The most visible casualty was the Windows
NCSI IPv6 connectivity probe (`ipv6.msftconnecttest.com`, `ipv6.msftncsi.com`),
whose relayed request died exactly this way and left the machine flagged
offline. Target-address selection is now aware of which address families can
actually be reached, and the plain-HTTP path fails in a defined way.

### Route-aware target selection

Address selection for the target host now consults which address families have
a usable route on this machine, reusing the same connected-UDP route probe that
already skips unroutable resolver endpoints. An address whose family has no
route here is no longer committed to when the other family is usable. The
fail-open behavior is preserved: when neither family probes usable the check
disengages and every address is still tried, exactly as before.

### Clean failure instead of a raw socket error

An AAAA-only name on a host without an IPv6 route now fails promptly and
cleanly as "no reachable address for this host," decided within the existing
resolution budget, rather than escaping as a bare connect-time socket error
(`WinError 10051`) partway through the relay.

### Defined response on the plain-HTTP relay path

A connect or resolve failure on the plain-HTTP path now returns
`HTTP/1.1 502 Bad Gateway`, mirroring the CONNECT path, instead of silently
closing the client connection. The 502 is scoped to the connect attempt only
and is never emitted once relaying has begun. A connectivity probe made through
the proxy now reaches the same verdict a direct connection on the same host
would, so an unreachable IPv6-only target no longer degrades the machine's
overall connectivity state to offline.

### DNS trust invariant unchanged

The route check is purely transport-level and is kept entirely separate from
resolution trust. It never lowers the trust of a DoH answer, never re-queries
an `A` record over plain UDP/TCP, and never reclassifies an authoritative DNS
negative. A verified DoH negative still terminates the chain immediately; an
unverified (plain UDP/TCP) negative still does not.

### Unchanged

The resolver chain order and its fallbacks, the positive and negative caches,
ClientHello fragmentation, and the dual-stack IPv4 preference are all untouched.
Genuine IPv6-only-network operation is preserved: an AAAA host still connects
over IPv6 whenever IPv6 has a usable route — IPv6 is not disabled. SNIper
remains standard-library only, with no admin rights, no new dependency and no
new process.

- The embedded version metadata (version_info.txt, app.manifest) is bumped to
  1.1.6.0 in this release to match the package version.

## v1.1.5 - 2026-06-17

A reliability release for Windows system-proxy restoration. Earlier builds kept
the "original proxy configuration to restore to" only in memory and captured it
unconditionally. An ungraceful exit (Task Manager force-kill, power loss, OS
logoff/shutdown) therefore left the system proxy pointed at a SNIper instance
that no longer existed, and a later restart could cement SNIper's own loopback
values as the "original", permanently destroying the genuine settings. The
restore baseline is now durable, self-healing and footprint-aware.

### Durable restore baseline

Before SNIper overwrites the live HKCU Internet Settings, it now records the
genuine pre-SNIper configuration (the ProxyEnable flag, the ProxyServer string,
and the AutoConfigURL PAC presence and value) to a durable per-user registry key
(HKCU\Software\SNIper\ProxyRestore), writing a commit marker last so a crash
mid-write leaves an incomplete record that is ignored rather than acted on.
Nothing is written to the filesystem; the baseline lives only in the registry.
This strengthens the existing partial-write safety: a baseline remains available
for restore even if enabling is interrupted partway through, and it now also
survives process death.

### Self-heal on launch

Every launch, before establishing a new proxy session, SNIper checks for a
baseline left behind by a prior unclean exit and, if it finds one, returns the
system proxy to that genuine configuration and clears the record. Merely opening
the app is enough to recover a proxy stranded by a previous force-kill, power
loss or shutdown; clicking Start is not required. A clean state is a no-op and
logs nothing, so there is no false "recovered" line.

### Footprint-aware capture (no more blind toggle)

SNIper distinguishes its own leftover footprint from the user's genuine
configuration using the durable record it writes, never by guessing from the
loopback address. It never records its own footprint as the baseline, and
applying the proxy is idempotent: if a complete baseline already exists it is
treated as the genuine one and reused untouched, so a re-apply (or an
already-applied state) cannot overwrite the real settings. Any number of
crash-then-relaunch cycles preserves the genuine original.

### Restore is complete and residue-free

A restore, whether the immediate graceful one or the deferred self-heal, puts
ProxyEnable, ProxyServer and AutoConfigURL all back to their genuine values,
removing SNIper's footprint entirely (it no longer leaves the proxy enabled and
pointed at loopback) and notifies WinInet so the change applies at once. After a
successful graceful restore the durable record is deleted, so the next launch
sees a clean state and performs no recovery; a clean exit leaves no proxy-related
residue. Restore now reads the durable registry record as its single source of
truth, so the graceful-stop path and the on-launch self-heal are one and the
same operation.

### Unchanged

Graceful exits (window close, Stop button, normal process exit) still restore
immediately. The Group Policy lock case is preserved: where per-user proxy is
policy-disabled SNIper changes nothing, writes no baseline, performs no false
recovery, and still shows its warning. The single-instance guard (still
session-local, so RDP and Fast User Switching sessions stay independent), PAC
handling, the WinInet refresh, the DNS resolution chain, ClientHello
fragmentation and the proxy relay core are untouched. No new dependency is added
(standard library only), no admin rights or helper process are introduced, and
all proxy state stays under HKCU.

### Also in this release: project restructure (GUI-only, modular package)

Pure structural refactor. Runtime behavior is unchanged: every function
behaves identically to v1.1.4, and this change only moves and re-organizes
code. No algorithm, timeout, server list, chain order or protocol detail was
touched.

- Removed the command-line variant (src/SNIper.py). SNIper is now GUI-only,
  matching how it is actually shipped (the portable EXE was always the GUI).
- The proxy logic that used to be duplicated between the CLI and the GUI is
  de-duplicated into a single layered package under src/sniper/ (compat,
  resources, config, dns, proxy, server, winproxy, logformat, tray, ui, app).
- DOH_SERVERS and PLAIN_DNS_SERVERS (and every other tunable) are now defined
  exactly once, in sniper/config.py, instead of as two hand-synced copies.
- The entry point is src/run_sniper.py (it calls sniper.app.main); running
  with "python -m sniper" works too. packaging/build_exe.bat points at it and
  adds src/ to the PyInstaller search path.
- Added a headless test suite under tests/ covering the DNS builder/parser,
  host:port splitting, HTTP response parsing and the friendly log formatter,
  checked against a golden baseline captured before the move.
- The embedded version metadata (version_info.txt, app.manifest) is bumped to
  1.1.5.0 in this release to match the package version.

## v1.1.4 — 2026-06-12

A resolver-correctness release. A CONNECT to a hostname that does not exist
anywhere (dead telemetry endpoints, removed CDN shards, typo'd hosts) used to
tie up its handler for ~6 seconds while every fallback was tried; it now fails
in a single DoH round-trip with one concise log line. The censorship-bypass
chain for real hosts is unchanged.

### DNS answers are classified, not collapsed

`_parse_dns_response` used to return `None` for everything that was not a
usable address, making an authoritative "this name does not exist" look
identical to "the resolver was unreachable". The parser now classifies every
response — POSITIVE, NXDOMAIN (RCODE 3), NODATA (NOERROR with no record of
the queried type) or TRANSPORT-FAIL (SERVFAIL, malformed, timeout, reset) —
so the resolution chain can act on the difference. Negative answers also
carry the RFC 2308 negative TTL taken from the authority section's SOA
record.

### Authoritative DoH negatives end the chain immediately

DoH answers arrive over verified TLS to a known resolver IP, so a clean
answer can be trusted. An NXDOMAIN from a DoH server now stops the whole
chain at once — no remaining DoH servers, no UDP/TCP fallback, no AAAA pass,
no system resolver — and the CONNECT fails immediately with a clear
"host does not exist (NXDOMAIN)" line instead of a cascade of per-server
warnings (previously up to ~60 lookups across six passes). A NODATA on the
A query means the name exists without IPv4, so the pointless UDP/TCP A
fallbacks are skipped and the AAAA path is tried directly; NODATA on both
families fails cleanly with "no usable address". AAAA-only hosts (e.g.
`ipv6.msftconnecttest.com`) still resolve exactly as before.

The trust boundary is deliberate: negatives received over plain UDP/53 or
TCP/53 are unauthenticated and spoofable, so they are still treated as
failures to route around — a poisoning ISP cannot convince SNIper to give up
on a name it is lying about. Certificate-verification failures remain
transport failures (never authoritative negatives) and keep the distinct
TLS-MITM warning.

### Unroutable address families are skipped

On an IPv4-only host every IPv6 resolver endpoint failed with
`WinError 10051` on every pass, adding latency and log noise. A
connected-UDP route probe (sends no packets — it only asks the kernel for a
route) now detects which address families are usable, caches the answer for
30 seconds, and the resolver skips endpoints of a family that has no route.
If neither family probes usable the filter disengages rather than skip
everything, and IPv6-only networks symmetrically skip the IPv4 entries.

### Negative caching and a resolution budget

NXDOMAIN and no-address answers are now cached (SOA-derived TTL clamped to
15–600 s, default 30 s; bounded to the same 1024 entries as the positive
cache), so repeated requests for the same dead host fail instantly.
Independently of the cache, one `resolve_doh` call is bounded by a 3-second
wall-clock budget (`RESOLVE_BUDGET`, separate from `CONNECT_TIMEOUT`, which
governs the TCP connect to the already-resolved IP): per-attempt timeouts
shrink to the remaining budget, the DoH A pass may use at most half of it so
a silently-dropped DoH path cannot starve the UDP/TCP bypass stages, and the
untimeboxable system-resolver step only runs while budget remains.

### Log output

The GUI's friendly formatter renders the new outcomes ("host does not
exist", "no IPv4/IPv6 address") in normal mode; verbose mode shows the raw
detail, including which DoH server returned the authoritative negative and
which unauthenticated negatives were ignored. The README note that called
errno 11001 warnings "harmless cold-cache misses" was corrected — for a
genuinely nonexistent name that error was the definitive answer, and it is
now recognised and reported as such.

## v1.1.3 — 2026-05-22

A compatibility-focused release. The goal was to let SNIper start and route
traffic unmodified on as many machine configurations as possible — different
Windows versions, Python versions, network types and hardware. Every change
below closes a specific case where the application could fail to start, fail
to bypass, or behave inconsistently.

### CLI runs on Python 3.7-3.9 again

`src/SNIper.py` and `src/SNIper_gui.py` used PEP 604 (`X | Y`) and PEP 585
(`tuple[...]`) type hints. A Python 3.9-or-older parser rejects those with a
`SyntaxError` before the module can load. Both files now begin with
`from __future__ import annotations`, so annotations are evaluated lazily and
the script imports cleanly on Python 3.7 and later. The EXE bundles its own
runtime and was never affected — this only matters when running the script
directly.

### Windows version claims corrected

`app.manifest` declared support for Windows 7 and 8, but the bundled Python
runtime depends on a Universal CRT version those releases do not ship, so the
EXE fails there with "this app can't run on your PC". The two false
`supportedOS` GUIDs were removed — the manifest now declares only Windows
10/11 and Windows 8.1 — and the README documents the real minimum
(Windows 10 1607). On older Windows 10 builds limited to Per-Monitor v1 DPI
awareness, the GUI now rescales when moved between monitors of different DPI
instead of staying blurry.

### DNS resolution on IPv6-only networks

On NAT64/DNS64, DS-Lite and 464XLAT networks there is no IPv4 path, so every
IPv4 DoH and plain-DNS resolver was unreachable and resolution failed:

- The DoH list and the plain-DNS list each gained IPv6 resolver addresses
  (Cloudflare, Google, AdGuard), tried after the IPv4 entries so dual-stack
  hosts still prefer the faster IPv4 path.
- The DoH URL parser is now IPv6-aware: a bracketed literal such as
  `https://[2606:4700:4700::1111]/dns-query` has its brackets stripped before
  the address reaches `socket.create_connection()`, which rejects the
  bracketed form.
- The resolver list was widened (AdGuard, DNS.SB), so a fast certificate
  failure on one provider falls through to a working one quickly.

### TLS handshake floor and certificate diagnostics

The DoH SSL context now sets `minimum_version = TLSv1_2` explicitly, removing
the version-dependent ambiguity between Python builds; the floor is kept at
1.2 (not 1.3) so the handshake still completes through TLS-MITM appliances
that lack 1.3 support. A DoH certificate-verification failure is now counted
and logged separately from an ordinary DPI reset or timeout — a recurring
warning is a clear signal that the connection is being intercepted by a MITM
CA trusted on the machine.

### Listener and connection handling hardened

- On Windows the listening socket now uses `SO_EXCLUSIVEADDRUSE` instead of
  `SO_REUSEADDR`. On Windows `SO_REUSEADDR` lets an unrelated process bind the
  same address and hijack connections; `SO_EXCLUSIVEADDRUSE` is the correct
  exclusive bind. Other platforms keep `SO_REUSEADDR`.
- Concurrent connection handlers are capped with a bounded semaphore (256). A
  burst of connections can no longer exhaust the OS thread limit and crash the
  accept loop; over the cap a connection is refused and the client retries.
- Remote sockets enable TCP keepalive (with a shortened Windows probe
  interval), so a peer that vanishes without a FIN/RST — laptop sleep, Wi-Fi
  change, NAT idle-timeout — no longer leaks a handler stuck forever in
  `recv()`.

### GUI on stock Windows 10

- The log panel asked for "Cascadia Mono", which ships in-box only on Windows
  11. When it is missing Tk silently substitutes a proportional font. The
  monospaced family is now resolved at runtime against the actual font list,
  falling back Cascadia Mono → Consolas → Lucida Console → Courier New.
- The window is clamped to the screen. On small displays (1366×768 and below),
  especially above 100% DPI scaling, the fixed 760×640 geometry plus chrome
  could spill off-screen; it now never requests more than the screen can show,
  and the minimum size was lowered to match.

### Tray icon survives an Explorer restart

When Explorer crashes and restarts it rebuilds the taskbar and drops every
tray icon. The tray helper is now a normal (hidden, tool-window) top-level
window rather than a message-only window — message-only windows do not receive
broadcasts — and it listens for the `TaskbarCreated` broadcast, re-adding the
icon so it reappears instead of staying gone.

### Corporate proxy environments

- **Group Policy:** if `ProxySettingsPerUser` is 0 under the HKLM policy key,
  Windows ignores the per-user proxy values SNIper writes — the write succeeds
  but has no effect. SNIper now detects this and logs a clear warning instead
  of failing silently on a managed machine.
- **PAC scripts:** an `AutoConfigURL` (PAC) is evaluated by Windows before the
  static proxy, so a PAC returning `DIRECT` would route around SNIper. The PAC
  value is now saved, temporarily cleared while SNIper runs, and restored on
  exit; the log notes when this happens.

### Bracketed IPv6 targets and a double-launch guard

- A `CONNECT [2001:db8::1]:443` request — the form modern browsers send for an
  IPv6 literal — previously kept the brackets and failed to resolve. Host/port
  splitting is now bracket-aware across both the CONNECT and plain-HTTP paths.
- A session-local named mutex makes a second launch fail fast with a clear
  message instead of two instances fighting over the proxy registry keys. The
  mutex is per-session, so RDP and Fast User Switching each get their own
  instance.

### Build script

- PyInstaller is pinned to `>=6.0,<7.0`, so a future major release cannot
  change CLI flags or hooks and break the build silently.
- The script resolves `sys.executable` before building. This proves a real
  interpreter answered — a bare `python` on PATH can be the Microsoft Store
  stub, which runs no code — and prints which Python is in use. It also warns
  when Python 3.13+ is used, since that runtime would raise the EXE's OS floor
  above the documented Windows 10 1607 minimum.
- The finished EXE's SHA-256 is printed in the build summary so the builder
  can publish it for verification (the EXE is unsigned).
- 32-bit Windows (x86) is detected and rejected with a clear explanation
  rather than a generic "unsupported architecture" message.

### Application icon

A dedicated `SNIper.ico` is embedded into the EXE and shown in the window
title bar, the taskbar, Alt-Tab and the system-tray entry. A generic
executable icon is both a low-reputation signal for antivirus heuristics and
makes the app hard to pick out among other tray icons.

### Documentation

The README gained a System Requirements section (minimum Windows and Python
versions) and explicit notes on the situations where a proxy-based bypass has
limits: antivirus HTTPS/TLS scanning re-exposing the SNI, SOCKS-only
applications, HTTP/3 (QUIC) over UDP, Firefox's own proxy and DoH settings,
WSL2, UWP apps, active VPNs, the `hosts` file and internal/LAN DNS being
bypassed while DoH is on, and a recommendation to run `ipconfig /flushdns`
after first launch. A SmartScreen / antivirus section explains why a new
unsigned build is flagged and how to add an exclusion.

---

## v1.1.2 — 2026-05-15

### DoH now survives TLS-MITM and provider quirks (RFC 8484 wire format)

Real-world testing on aggressively filtered networks surfaced three
independent failures that left DoH unusable, forcing every lookup down to
plain UDP DNS — which is itself poisoned for blocked hostnames:

1. **DoH ClientHello sent in a single TCP segment.** The resolver used
   `urllib`, which hands the whole TLS ClientHello to the OS in one write.
   DPI engines that fingerprint or RST-inject DoH connections dropped every
   request. The resolver now drives the TLS handshake by hand through SSL
   BIOs and splits the first write (the ClientHello) into 2-byte TCP
   segments — the same evasion the proxy already applies to client traffic.
2. **JSON DoH is not portable.** `application/dns-json` works on Cloudflare
   but Google rejects it at `/dns-query` (HTTP 400 — JSON only lives at the
   non-standard `/resolve`), and other providers answered 400/505
   inconsistently. DoH now uses the **RFC 8484 binary wire format**
   (`application/dns-message`): the query is the same packet the UDP path
   builds, base64url-encoded into `?dns=`, and the reply is parsed by the
   existing DNS message parser. No JSON, no per-provider divergence.
3. **TLS-MITM on Cloudflare resolver IPs.** Some ISPs present a forged
   certificate for `1.1.1.1` / `1.0.0.1`, so verification correctly fails
   (accepting it would hand DNS to the interceptor). The server list was
   reordered and widened so a fast cert failure on Cloudflare falls through
   to a working resolver in well under a second.

### DoH server list

Quad9 (`9.9.9.9`) was removed — it enforces HTTP/2 (RFC 8484 §5.2), which
the standard library does not implement, so it always returned 505. AdGuard
(`94.140.14.14`, `94.140.15.15`) and DNS.SB (`185.222.222.222`) were added;
both are rarely MITM'd or IP-blocked and answer the binary wire format over
HTTP/1.1. New order: Cloudflare → Google → AdGuard → Cloudflare 2 →
Google 2 → DNS.SB.

### Plain TCP DNS fallback (RFC 7766)

Between the public UDP DNS step and the system-resolver last resort, the
chain now also tries DNS over TCP/53 to the same public resolvers. Networks
that rewrite UDP/53 responses frequently leave TCP/53 untouched. Full chain:
**DoH-A → UDP-A → TCP-A → DoH-AAAA → UDP-AAAA → TCP-AAAA → getaddrinfo**.

### Project restructure & rename

Files were renamed to match the project (`SNIper`) and organised into a
conventional layout:

- `dpi_bypass.py` → `src/SNIper.py`
- `dpi_bypass_gui.py` → `src/SNIper_gui.py`
- `build_exe.bat`, `app.manifest`, `version_info.txt` → `packaging/`
- The built executable is now `SNIper_<arch>.exe` (was
  `DPI_Bypass_Proxy_<arch>.exe`), dropped at the project root.

EXE metadata, window title, tray tooltip, log channel and the CLI banner
were rebranded to **SNIper**; embedded version bumped to `1.1.2.0`. The
`build_exe.bat` console output (previously partly Turkish) is now fully
English.

---

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
