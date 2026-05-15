# SNIper

A lightweight, zero-dependency DPI bypass proxy written in pure Python, shipped
as a portable Windows `.exe`.

It runs entirely at the **application layer**: no admin privileges, no kernel
drivers, no TAP adapters, no service installs. Just double-click the `.exe`
from any folder (USB stick, Downloads, Desktop) and it works for the current
user only.

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

## Project layout

```
SNIper_v1.1.2/
├── README.md                  This file
├── LICENSE                    MIT License
├── CHANGELOG.md               Version history
├── .gitignore
├── src/
│   ├── SNIper_gui.py          GUI front-end (all proxy logic embedded)
│   └── SNIper.py              CLI core (no GUI)
└── packaging/
    ├── build_exe.bat          Build the portable EXE for this architecture
    ├── app.manifest           asInvoker (no UAC) + Per-Monitor v2 DPI
    └── version_info.txt       EXE metadata (anti-false-positive)
```

The built executable (`SNIper_<arch>.exe`) is dropped at the project root,
next to this README, after running `packaging\build_exe.bat`.

| Path | Purpose |
|------|---------|
| `src/SNIper_gui.py` | GUI source — the file PyInstaller packages into the EXE |
| `src/SNIper.py` | CLI source (no GUI), for scripting / headless use |
| `packaging/build_exe.bat` | Rebuild `SNIper_<arch>.exe` for the current architecture |
| `SNIper_<arch>.exe` | Portable GUI executable, produced by the build script |

> **Note on architectures:** PyInstaller does not cross-compile, so each EXE
> must be built on a machine of its own architecture. To produce the x64
> build, run `packaging\build_exe.bat` on an x64 Windows machine; for ARM64,
> run it on an ARM64 machine.

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
| Power loss / force kill | No, disable manually in Settings → Network → Proxy |

## Notes

- **errno 11001** warnings in the log are harmless. They occur on the very
  first request to a new domain when DoH hasn't cached it yet and the system
  DNS can't resolve it (because it's blocked). The next request succeeds via
  DoH and the result is cached.
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
