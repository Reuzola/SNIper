# SNIper

A lightweight, zero-dependency DPI bypass proxy written in pure Python, shipped
as a portable Windows `.exe`.

It runs entirely at the **application layer**: no admin privileges, no kernel
drivers, no TAP adapters, no service installs. Just double-click the `.exe`
from any folder (USB stick, Downloads, Desktop) and it works for the current
user only.

## System requirements

- **Operating system:** Windows 10, version 1607 (Anniversary Update) or
  later, or Windows 11. Both x64 and ARM64 are supported. Windows 7 and 8
  are **not supported**: the bundled Python runtime depends on a Universal
  CRT version that does not ship on those releases, so the EXE will fail
  to start with a "this app can't run on your PC" error. Windows 8.1 may
  load the EXE with the latest servicing updates installed, but is
  untested and not officially supported.
- **Python (CLI only):** if you run `src/SNIper.py` directly instead of
  the EXE, you need **Python 3.10 or newer**. The EXE bundles its own
  runtime, so this requirement only applies to the CLI script.

## Origin

This project started from a personal need. I have an ARM64 Windows machine and
couldn't find a working, pre-built DPI bypass tool for that architecture. Most
existing solutions ship compiled binaries, none of them ran natively on ARM64,
and most of them required admin rights or driver installs.

So I described the problem to **[Claude](https://claude.ai)** (Anthropic's AI
assistant) and asked it to write one from scratch in pure Python, which has no
architecture dependency and runs entirely in user-space. After a few iterations
of feeding errors back and refining, this is the result. The final code is
entirely Claude's work; my role was defining the requirements and testing.

I'm publishing it in case anyone else runs into the same gap.

## How it works

ISP-level blocking in many countries uses **SNI-based Deep Packet Inspection**:
the firewall reads the `Server Name Indication` field inside the TLS
ClientHello packet to identify the destination, then drops the connection.

This tool defeats that in two ways:

**1. TLS ClientHello fragmentation**
The ClientHello is split into 2-byte TCP segments with Nagle's algorithm
disabled (`TCP_NODELAY`). Each fragment travels in its own TCP segment, so the
DPI engine never sees the full SNI field in one piece and lets the connection
through.

**2. DNS-over-HTTPS**
DNS queries are sent over HTTPS directly to IP addresses (`1.1.1.1`, `8.8.8.8`,
etc.), bypassing the ISP's DNS servers entirely. This prevents DNS poisoning,
which is a common secondary blocking method. A TTL-aware in-memory cache avoids
redundant lookups.

Everything runs in a single user-space process. The Windows system proxy is
toggled via the per-user `HKEY_CURRENT_USER` registry key, which **does not
require elevation**.

## Usage

### Just run the EXE

**Double-click `SNIper_<arch>.exe`**. No install, no admin prompt,
no dependencies.

A window opens with all settings visible. Press **START** to activate the proxy
and the Windows system proxy is enabled automatically. Press **STOP** (or close
the window) to shut down and restore your previous proxy settings.

The EXE is fully portable: copy it anywhere (USB drive, OneDrive, etc.) and it
will run from there. It writes nothing to the registry except the per-user
proxy settings, which it restores on exit.

## Antivirus and SmartScreen

The first time you run a freshly downloaded `SNIper_<arch>.exe`, Windows
SmartScreen or a third-party antivirus may warn about it or move it to
quarantine. This is expected for a new, unsigned executable and does not mean
the file is malicious — several of SNIper's normal actions overlap with
behaviour that heuristic scanners treat as suspicious:

- it opens a local TCP listener and proxies traffic (server-like behaviour);
- it writes the per-user proxy keys in the registry;
- it can open many outbound connections in a short burst;
- the EXE is **not code-signed**, so SmartScreen has no reputation history
  for it and every new release starts from a zero-reputation baseline.

None of this is hidden — the full source is in this repository, and you can
build the EXE yourself (see *Building from source*) instead of trusting a
pre-built binary.

### Getting past SmartScreen

If you see **"Windows protected your PC"**, click **More info**, then
**Run anyway**. The EXE carries embedded version metadata, an application
manifest and an icon, all of which help its reputation, but a brand-new
download still has to be allowed through manually the first time.

### If your antivirus quarantines it

If Microsoft Defender or a third-party product (Avast, Kaspersky,
Bitdefender, etc.) removes or blocks the EXE, restore it and add an
exclusion. In **Windows Security**:

1. Open **Windows Security → Virus & threat protection**.
2. Under **Virus & threat protection settings**, click **Manage settings**.
3. Scroll to **Exclusions** and click **Add or remove exclusions**.
4. Choose **Add an exclusion → File** and select `SNIper_<arch>.exe`.

For third-party antivirus software, use its equivalent "exclusion" or
"allow list" feature. Only exclude files you trust — building the EXE
yourself from source is the surest way to know what you are allowing.

## Project layout

```
SNIper_v1.1.2/
├── README.md                  This file
├── LICENSE                    MIT License
├── CHANGELOG.md               Version history
├── .gitignore
├── SNIper_arm64.exe           Pre-built portable GUI (ARM64 Windows)
├── src/
│   ├── SNIper_gui.py          GUI front-end (all proxy logic embedded)
│   └── SNIper.py              CLI core (no GUI)
└── packaging/
    ├── build_exe.bat          Build the portable EXE for this architecture
    ├── app.manifest           asInvoker (no UAC) + Per-Monitor v2 DPI
    ├── version_info.txt       EXE metadata (anti-false-positive)
    └── SNIper.ico             Application icon embedded into the EXE
```

This release ships with a pre-built **ARM64** executable
(`SNIper_arm64.exe`) at the project root — just double-click it, no build
step needed. To produce an x64 build, run `packaging\build_exe.bat` on an
x64 Windows machine; the script drops `SNIper_x64.exe` next to this README
and verifies its architecture before finishing.

| Path | Purpose |
|------|---------|
| `SNIper_arm64.exe` | Pre-built portable GUI executable (ARM64 Windows) — ready to run |
| `src/SNIper_gui.py` | GUI source — the file PyInstaller packages into the EXE |
| `src/SNIper.py` | CLI source (no GUI), for scripting / headless use |
| `packaging/build_exe.bat` | Rebuild `SNIper_<arch>.exe` for the current architecture |

> **Note on architectures:** PyInstaller does not cross-compile, so each EXE
> must be built on a machine of its own architecture. The shipped
> `SNIper_arm64.exe` runs on ARM64 Windows; for x64, run
> `packaging\build_exe.bat` on an x64 Windows machine.

## Why no admin prompt?

Most DPI-bypass tools you'll find online either:

- install a driver (WinDivert, WFP, etc.), which requires admin and persists across
  reboots even after "uninstall"; or
- run a system service, which requires admin and adds an attack surface.

This tool does **neither**. It is a plain HTTP/CONNECT proxy that:

- listens on `127.0.0.1` (no firewall rule needed);
- forwards traffic with a userland fragmentation trick on the very first TCP
  send (no kernel involvement);
- toggles the per-user proxy via `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
  (admin rights are not needed to write to your own user hive).

If you launch it from a non-elevated shell, which is the default, Windows
never shows a UAC prompt and the program runs at the standard user integrity
level.

## GUI overview

The GUI provides:

- **Settings panel**: configure all options before starting. Hover over the
  `?` button next to any setting for a description of what it does and how to
  adjust it if something isn't working.
- **Start / Stop button**: toggle the proxy on and off without closing the
  application. Settings are locked while the proxy is running.
- **Live log panel**: shows all connections and warnings in real time,
  colour-coded by severity. A Clear button keeps it tidy.
- **Status indicator**: shows whether the proxy is currently running.

## Running the CLI version (optional)

The repository also ships the CLI script (`src/SNIper.py`) for users who want
to embed the proxy in their own scripts or run it without a GUI. This is
**not** packaged into the EXE; to use it you need a Python install:

```
python src/SNIper.py [options]

  --port N        Listen port (default: 8881)
  --fragment N    ClientHello fragment size in bytes (default: 2)
  --no-doh        Disable DNS-over-HTTPS, use system DNS instead
  --verbose       Enable debug logging
```

If the default settings don't work, try `--fragment 1` for more aggressive
fragmentation.

## Settings reference

| Setting | Default | What it does | When to change |
|---------|---------|-------------|----------------|
| Port | 8881 | Local port the proxy listens on | Change if another app is using 8881 |
| Fragment size | 2 | Bytes per TCP segment during TLS handshake | Try 1 if connections are refused; try 4-8 if performance suffers on non-blocked sites |
| Disable DoH | off | Falls back to system DNS | Enable only if DoH itself is timing out and system DNS resolves fine |
| Verbose | off | Shows debug-level log entries | Enable when troubleshooting |

## Proxy shutdown guarantee

The Windows proxy is restored under all normal exit conditions:

| Exit method | Proxy restored? |
|-------------|----------------|
| Close window (X button) | Yes |
| Stop button (GUI) | Yes |
| Ctrl+C (CLI) | Yes |
| Normal script exit | Yes |
| Power loss / force kill | No — disable the proxy manually in Settings → Network → Proxy; a PAC script, if you used one, also stays disabled |

## Notes

- **errno 11001** warnings in the log are harmless. They occur on the very
  first request to a new domain when DoH hasn't cached it yet and the system
  DNS can't resolve it (because it's blocked). The next request succeeds via
  DoH and the result is cached.
- **While DoH is active, your `hosts` file and any internal/LAN DNS are
  bypassed.** DNS-over-HTTPS resolves names straight from public resolvers,
  so entries in `C:\Windows\System32\drivers\etc\hosts`, corporate intranet
  names (`intranet.company.local`), local development hostnames
  (`myapp.local`), and network-level ad-blockers (Pi-hole, AdGuard Home) will
  not resolve. If you depend on any of these, run with `--no-doh` (CLI) or
  tick **Disable DoH** in the GUI.
- **Stale DNS after first launch.** If a site misbehaves right after you
  start SNIper, Windows may be serving a cached (possibly poisoned) DNS entry
  from before the proxy was active. Run `ipconfig /flushdns` once in a
  terminal to clear it, then retry.
- **Some software bypasses the Windows system proxy.** SNIper routes
  traffic by setting the Windows per-user proxy, which Chrome, Edge, Steam
  and most apps set to "use system proxy" will honour. **Firefox** is the
  main exception — by default it uses its own proxy settings and its own
  DNS-over-HTTPS, so SNIper has no effect until you switch it to "Use system
  proxy settings" under Settings → Network Settings. Likewise, any host
  listed in the Windows proxy *exceptions* (`ProxyOverride`) list is sent
  direct and skips SNIper.
- **On corporate machines, proxy changes may be blocked or overridden.** If
  Group Policy disables per-user proxy settings, SNIper logs a warning and
  cannot route traffic on that machine. If a PAC script (`AutoConfigURL`) is
  configured, SNIper temporarily disables it while running and restores it
  on exit.
- **On managed/corporate machines, DoH itself can still be intercepted.**
  SNIper validates each DoH server's TLS certificate against the Windows
  certificate store. If an extra root CA has been installed — common with
  corporate device management (MDM) or antivirus HTTPS scanning — traffic to
  the DoH resolvers can be transparently decrypted by that CA, which
  re-exposes your DNS lookups to inspection or poisoning. SNIper logs a
  warning when a DoH certificate fails verification; a recurring warning is a
  strong hint this is happening. On a personal, unmanaged machine this does
  not apply.
- Traffic is not encrypted by this tool, it only tunnels your existing HTTPS
  connections. Your TLS encryption remains intact end-to-end.
- The EXE is large (~10 MB) because PyInstaller bundles the Python runtime
  inside it. There are no external dependencies and nothing is extracted to
  disk on launch beyond the standard PyInstaller temp directory, which is
  cleaned up automatically.

## Building from source

If you want to build the EXE yourself (e.g. to inspect the bundle, or to
produce a build for a different architecture):

```
packaging\build_exe.bat
```

This installs PyInstaller into the active Python and produces
`SNIper_<arch>.exe` at the project root. The architecture is taken from the
Python interpreter, so to produce the x64 build, run the script with an x64
Python on an x64 host.

## Disclaimer

This tool is published for **educational and personal use**. It is intended to
help users access content that is legally available to them but technically
obstructed by ISP-level filtering.

- Use it in accordance with the laws of your country.
- The author takes no responsibility for any misuse.
- This tool does not encrypt traffic or provide anonymity; it only bypasses
  SNI-based filtering.
