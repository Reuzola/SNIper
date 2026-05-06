<div align="center">

# SNIper

**Lightweight DPI bypass proxy for Windows — ARM64 & x86**

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078d4?style=flat-square&logo=windows&logoColor=white)](https://github.com/Reuzola/SNIper)
[![ARM64](https://img.shields.io/badge/ARM64-native-success?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-zero-brightgreen?style=flat-square)]()

</div>

---

## What is SNIper?

SNIper is a local HTTP proxy that defeats ISP-level **SNI-based Deep Packet Inspection** (DPI) — the most common method used to block HTTPS traffic — by fragmenting the TLS ClientHello packet before the firewall can inspect it.

It comes in two flavors: a **GUI application** for everyday use, and a **CLI version** for headless or scripted setups. Both run in **pure Python** with zero third-party dependencies, making them natively compatible with **ARM64 Windows** — an architecture most pre-built tools don't support.

---

## Origin

This project started from a personal need. I have an ARM64 Windows machine and couldn't find a working DPI bypass tool for that architecture. Most existing solutions ship compiled binaries — none of them ran natively on ARM64.

I described the problem to **[Claude](https://claude.ai)** (Anthropic's AI assistant) and had it write the solution from scratch in pure Python. After several iterations — feeding errors back and refining — this is the result. I'm publishing it in case anyone else runs into the same gap.

---

## How it works

ISPs block HTTPS traffic by reading the `Server Name Indication` (SNI) field in the TLS ClientHello packet. SNIper defeats this with two mechanisms:

### 1 — TLS ClientHello Fragmentation

The ClientHello packet is split into 2-byte TCP segments with Nagle's algorithm disabled (`TCP_NODELAY`). Each fragment travels in its own TCP segment, so the DPI engine never sees the complete SNI field and lets the connection through.

```
Normal:   [ ——————— ClientHello (SNI visible) ——————— ]  →  ✗ BLOCKED
SNIper:   [ CH ] [ el ] [ lo ] [ He ] [ ll ] [ o→ ]   →  ✓ PASSES
```

### 2 — DNS-over-HTTPS (DoH)

DNS queries bypass the ISP's resolvers entirely by going over HTTPS directly to IP addresses (`1.1.1.1`, `8.8.8.8`, etc.). This prevents DNS poisoning — a common secondary blocking method. Results are cached in-memory with TTL awareness to avoid redundant lookups.

---

## Requirements

- Windows (ARM64 or x86)
- Python 3.9 or newer — [python.org/downloads](https://www.python.org/downloads/)
- No third-party packages

---

## Installation

```bash
git clone https://github.com/Reuzola/SNIper.git
cd SNIper
```

No pip install, no virtualenv, no setup step.

---

## Usage

### GUI (recommended)

**Double-click `dpi_bypass_gui.bat`**

A window opens with all settings visible. Press **START** to activate the proxy — the Windows system proxy is enabled automatically. Press **STOP** (or close the window) to shut down and restore your previous proxy settings.

### CLI

**Double-click `dpi_bypass.bat`**

The proxy starts immediately on port `8881` with default settings. Close the window or press `Ctrl+C` to stop.

Or run directly with options:

```bash
python dpi_bypass.py [options]

  --port N        Listen port (default: 8881)
  --fragment N    ClientHello fragment size in bytes (default: 2)
  --no-doh        Disable DNS-over-HTTPS, use system DNS instead
  --verbose       Enable debug logging
```

If the default settings don't unblock a site, try `--fragment 1` for more aggressive fragmentation.

---

## GUI overview

| Element | Description |
|---------|-------------|
| **Settings panel** | Configure port, fragment size, DoH, and verbosity before starting. Each setting has a `?` tooltip explaining what it does and when to change it. Settings are locked while the proxy is running. |
| **Start / Stop** | Toggle the proxy on and off without closing the application. |
| **Status indicator** | Shows `RUNNING` or `STOPPED` at a glance. |
| **Live log** | Real-time connection log, colour-coded by severity (info / warning / error / debug). Includes a Clear button. |

---

## Settings reference

| Setting | Default | What it does | When to change |
|---------|---------|-------------|----------------|
| Port | `8881` | Local port the proxy listens on | Change if another app is using 8881 |
| Fragment size | `2` | Bytes per TCP segment during TLS handshake | Try `1` if connections are refused; try `4–8` if performance suffers on non-blocked sites |
| Disable DoH | off | Falls back to system DNS | Enable only if DoH itself is timing out and system DNS resolves fine |
| Verbose | off | Shows debug-level log entries | Enable when troubleshooting |

---

## Files

| File | Purpose |
|------|---------|
| `dpi_bypass_gui.py` | GUI application — proxy logic embedded, recommended for most users |
| `dpi_bypass_gui.bat` | Double-click launcher for the GUI |
| `dpi_bypass.py` | CLI proxy — no GUI, suitable for scripting or headless use |
| `dpi_bypass.bat` | Double-click launcher for the CLI |

---

## Proxy shutdown guarantee

| Exit method | Proxy restored? |
|-------------|----------------|
| Close window (X button) | ✅ Yes |
| Stop button (GUI) | ✅ Yes |
| Ctrl+C (CLI) | ✅ Yes |
| Normal script exit | ✅ Yes |
| Power loss / force kill | ❌ No — restore manually via Settings → Network → Proxy |

---

## Notes

- **errno 11001 warnings** are harmless. They appear on the first request to a new domain when DoH hasn't cached it yet and system DNS can't resolve it (because it's blocked). The next request succeeds via DoH and is cached.
- SNIper does **not** encrypt your traffic — it tunnels your existing HTTPS connections. End-to-end TLS encryption remains fully intact.
- No admin privileges, kernel drivers, or TAP adapters required.
- Works at the application layer only. VPN-style global routing is out of scope by design.

---

## Disclaimer

This tool is published for **educational and personal use**. It is intended to help users access content that is legally available to them but technically obstructed by ISP-level filtering.

- Use it in accordance with the laws of your country.
- The author takes no responsibility for misuse.
- SNIper does not provide anonymity — it only bypasses SNI-based filtering.

---

<div align="center">

Made with the help of [Claude](https://claude.ai) · MIT License · [Reuzola](https://github.com/Reuzola)

</div>
