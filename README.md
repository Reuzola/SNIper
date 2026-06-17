# SNIper

A lightweight, zero-dependency DPI bypass proxy written in pure Python, shipped
as a portable Windows `.exe`.

It runs entirely at the **application layer**: no admin privileges, no kernel
drivers, no TAP adapters, no service installs. Just double-click the `.exe`
from any folder and it works for the current user only.

It is pre-configured and offered as a **plug-and-play** solution. All you have to do is
press the start button. You can easily monitor what is happening through a live activity log.

---

## Origin

This project started from a personal need. I have an ARM64 Windows machine and
could not find a working, pre-built DPI bypass tool for that architecture. Most
existing solutions ship compiled binaries, none of them ran natively on ARM64,
and most of them required admin rights or driver installs.

So I described the problem to Claude and asked it to write one from scratch in
pure Python, which has no architecture dependency and runs entirely in user-space.
After many rounds of feeding errors back and refining, this is the result, and it
is still being developed. I do a lot of testing and read detailed logs to improve
the stability and compatibility of the code.

I am publishing it in case anyone else runs into the same gap.

---

## What it does and why it works

ISPs in many countries block websites by reading the `Server Name Indication`
field inside the TLS ClientHello packet. The ClientHello is the very first
thing your browser sends when it opens an HTTPS connection, and it contains
the hostname in plain text, even though the rest of the connection is
encrypted. The firewall reads that hostname, recognizes a blocked site, and
drops the connection before anything else happens.

SNIper breaks this in two ways.

**ClientHello fragmentation.** Instead of sending the ClientHello as one
packet, SNIper cuts it into 2-byte TCP segments with Nagle's algorithm
disabled. Each fragment travels separately, so the DPI engine never sees the
complete SNI field in a single packet and lets the connection through. The
rest of the connection runs at full speed; only the handshake is fragmented.

**DNS-over-HTTPS.** Many ISPs also run DNS poisoning: when you look up a
blocked domain, their DNS server returns a wrong address. SNIper sends DNS
queries over HTTPS directly to public resolvers (Cloudflare, Google, AdGuard,
DNS.SB), bypassing the ISP's DNS entirely. If those HTTPS endpoints are
themselves blocked, it falls back to plain DNS over TCP and UDP to the same
public resolvers. The system DNS is only used as a last resort.

All of this runs in a normal user-space process. No admin rights, no kernel
drivers, no TAP adapters, no service install.

---

## System requirements

- Windows 10 version 1607 (Anniversary Update) or later, or Windows 11.
  Both x64 and ARM64 are supported.
- Windows 7, 8, and 8.1 are not supported. The bundled Python runtime
  depends on a Universal CRT version that does not ship on those releases.
  The EXE will fail to start with a "this app can't run on your PC" error.
- If you build or run from source instead of using the EXE, you need Python
  3.7 or newer. The EXE bundles its own runtime and has no Python requirement.

---

## Running the EXE

Double-click `SNIper_<arch>.exe`. No install step, no admin prompt, nothing
to configure first.

A window opens. Press **Start** to turn the proxy on. SNIper sets the Windows
system proxy automatically so Chrome, Edge, Steam, and most other apps route
through it right away. Press **Stop** or close the window to turn it off and
restore your previous proxy settings.

The EXE is fully portable. Copy it to a USB drive, your desktop, or anywhere
else and it works from any location. It writes nothing to disk except the
per-user proxy registry keys, which it restores on exit.

---

## GUI overview

- **Settings panel:** configure port, fragment size, and other options
  before you start. Hover over the `?` button next to any setting to see
  what it does.
- **Start / Stop button:** toggles the proxy without closing the window.
  Settings are locked while the proxy is running.
- **Activity log:** shows connections and warnings in real time, with a
  Clear button to keep it tidy.
- **Status indicator:** shows whether the proxy is currently running.
- **Hide to tray:** minimizes to the system tray. Right-click the tray
  icon to start/stop the proxy or quit.

---

## Settings

| Setting | Default | What it does | When to change it |
|---|---|---|---|
| Port | 8881 | Local port the proxy listens on | Change if another app is already using 8881 |
| Fragment size | 2 | Bytes per TCP segment during the TLS handshake | Try 1 if connections are being refused; try 4-8 if non-blocked sites feel slow |
| Disable DoH | off | Uses system DNS instead of DNS-over-HTTPS | Turn on only if DoH is timing out and system DNS works fine on its own |
| Verbose | off | Shows all internal debug messages in the log | Turn on when troubleshooting a specific problem |

---

## Antivirus and SmartScreen

The first time you run a newly downloaded `SNIper_<arch>.exe`, Windows
SmartScreen or your antivirus may warn about it or move it to quarantine.
This is expected behaviour for a new unsigned executable and does not mean
the file is malicious. Several things SNIper does normally look suspicious
to heuristic scanners: it opens a local TCP listener, it writes proxy
settings to the registry, and it can open many outbound connections quickly.
The full source is in this repository, and you can build the EXE yourself
if you prefer not to trust a pre-built binary.

**To get past SmartScreen:** if you see "Windows protected your PC", click
**More info**, then **Run anyway**.

**If your antivirus quarantines the file:** restore it and add an exclusion.
In Windows Security, go to Virus and threat protection settings, scroll to
Exclusions, and add the EXE as a file exclusion. For third-party antivirus
software, use its equivalent allow-list feature.

**A note on antivirus HTTPS scanning.** Products like ESET, Kaspersky,
Bitdefender, Norton, Avast, and others include an HTTPS scanning feature
that intercepts TLS traffic using the antivirus's own certificate, acting
as a local man-in-the-middle. When this is active, SNIper's fragmented
ClientHello reaches the antivirus first. The antivirus reassembles it and
opens its own un-fragmented connection to the destination, so the DPI device
sees an intact SNI and the block comes back. If sites stay blocked while
SNIper is running, disable your antivirus's HTTPS/TLS scanning feature and
try again.

---

## Known limitations

**Firefox** uses its own proxy settings and its own DNS-over-HTTPS by
default, so SNIper has no effect on it until you change Firefox's network
settings to use the system proxy.

**SOCKS-only apps** such as some BitTorrent clients and Tor cannot use
SNIper. It is an HTTP CONNECT proxy, not a SOCKS proxy.

**HTTP/3 (QUIC)** runs over UDP, which SNIper's TCP proxy cannot carry.
Chrome and Edge try HTTP/3 first and fall back to TCP within a second or
two, so most sites still load. If a blocked site is reliably slow to open,
disabling QUIC in browser flags can help.

**WSL2** does not inherit the Windows system proxy. To send a WSL2 program
through SNIper, set `http_proxy` and `https_proxy` inside Linux, pointing
at the Windows host address (not 127.0.0.1) on port 8881.

**UWP apps** (Windows Store apps) behave inconsistently. Some honour the
system proxy, others do their own networking.

**Active VPNs** send traffic through their own network adapter, which may
bypass the Windows system proxy entirely. With a VPN connected, SNIper may
have no effect.

**Corporate/managed machines.** If Group Policy sets `ProxySettingsPerUser`
to 0, Windows ignores the per-user proxy values SNIper writes. SNIper
detects this and logs a warning. If your machine has a PAC script configured
(AutoConfigURL), SNIper temporarily disables it while running and restores
it on exit.

**The hosts file and local DNS** are bypassed while DoH is active. SNIper
sends names directly to public resolvers, so entries in your hosts file,
intranet names, local dev hostnames, and network-level ad-blockers (Pi-hole,
AdGuard Home) will not resolve. Run with `--no-doh` or tick Disable DoH in
the GUI if you need any of these.

**Stale DNS after first launch.** If a site misbehaves right after you start
SNIper, Windows may be serving a cached poisoned DNS entry from before the
proxy was active. Run `ipconfig /flushdns` once in a terminal and retry.

**On corporate machines, DoH can still be intercepted** if an extra root CA
has been installed (common with MDM or antivirus HTTPS scanning). SNIper
validates each DoH server's certificate. A recurring certificate warning in
the log is a strong hint this is happening.

**"host does not exist (NXDOMAIN)" messages** mean a client asked for a
hostname that genuinely has no DNS entry — dead telemetry endpoints, removed
CDN hosts, typo'd domains. SNIper confirms this with an authenticated DoH
resolver, rejects the request immediately and briefly caches the negative
answer, so these lines are expected and harmless. A transient `errno 11001`
without the NXDOMAIN wording can still appear in the rare case the whole DNS
chain was momentarily unreachable; that one resolves itself on the next
request.

**Power loss or force-kill** cannot restore the proxy at the instant it
happens, because no SNIper code runs at that moment. Instead the proxy is
restored automatically the next time you launch SNIper: it detects the
settings left behind by the unclean exit and puts your original proxy
configuration back before starting a new session. Just opening the app is
enough, with no need to click Start and no manual editing of Windows
proxy settings. Graceful exits (X, Stop, normal exit) still restore
immediately.

---

## What gets restored on exit

| How you exit | Proxy restored? |
|---|---|
| Close window (X button) | Yes, immediately |
| Stop button in the GUI | Yes, immediately |
| Normal process exit | Yes, immediately |
| Power loss or force-kill | Yes, automatically on next launch |

---

## Project layout

```
SNIper_v1.1.5/
  README.md
  LICENSE
  CHANGELOG.md
  .gitignore
  src/
    run_sniper.py           PyInstaller entry point (-> sniper.app.main)
    sniper/
      __init__.py           package version
      __main__.py           enables `python -m sniper`
      compat.py             IS_WINDOWS flag + winreg shim
      resources.py          locates the bundled SNIper.ico
      config.py             tunables, DoH/plain-DNS server lists
      dns.py                resolver chain (DoH/UDP/TCP, caches, parser)
      proxy.py              per-connection handling, ClientHello fragmentation
      server.py             ProxyServer accept-loop thread
      winproxy.py           Windows system-proxy registry management
      logformat.py          friendly activity-log formatter
      tray.py               Win32 system-tray icon
      ui.py                 Tk application window
      app.py                main(), single-instance guard
  packaging/
    build_exe.bat           Build the portable EXE for this architecture
    app.manifest            asInvoker (no UAC) + Per-Monitor v2 DPI awareness
    version_info.txt        EXE version metadata
    SNIper.ico              Application icon
  tests/
    conftest.py             puts src/ on sys.path
    test_dns.py             DNS builder/parser equivalence tests
    test_proxy.py           host:port, ClientHello and header tests
    test_logformat.py       friendly-formatter tests
```

To produce an x64 or ARM64 build, run `packaging\build_exe.bat` on a
machine of the target architecture. PyInstaller does not cross-compile,
so each architecture requires its own native build.

To run from source without building, use `python src/run_sniper.py` (or
`python -m sniper` from inside `src/`). This needs Python 3.7 or newer.

---

## Building from source

```
packaging\build_exe.bat
```

The script installs PyInstaller if it is not already present, builds a
single-file EXE for the architecture of the Python interpreter it runs
under, and drops `SNIper_<arch>.exe` at the project root. It also prints
the SHA-256 of the finished EXE so you can publish a checksum for others
to verify.

---

## Disclaimer

This tool is published for educational and personal use. It is intended to
help users access content that is legally available to them but technically
obstructed by ISP-level filtering. Use it in accordance with the laws of
your country. The author takes no responsibility for misuse. This tool does
not encrypt traffic or provide anonymity; it only bypasses SNI-based
filtering. Your existing TLS encryption remains intact end-to-end.