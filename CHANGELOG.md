# Changelog

All notable changes to SNIper are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
Versions follow [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`

> **MAJOR** — breaking change or complete redesign  
> **MINOR** — new feature, backwards-compatible  
> **PATCH** — bug fix or small improvement

---

## [Unreleased]

_Changes staged for the next release go here._

---

## [1.0.0] — 2025-05-07

### Added
- GUI application (`dpi_bypass_gui.py`) with settings panel, start/stop toggle, live colour-coded log, and status indicator
- CLI proxy (`dpi_bypass.py`) for headless and scripted use
- TLS ClientHello fragmentation — configurable segment size (default: 2 bytes)
- DNS-over-HTTPS via Cloudflare (`1.1.1.1`, `1.0.0.1`), Google (`8.8.8.8`), and Quad9 (`9.9.9.9`)
- TTL-aware in-memory DNS cache
- Automatic Windows system proxy configuration on launch and restore on exit
- Graceful shutdown on window close (X button), Stop button, Ctrl+C, and normal exit
- Double-click `.bat` launchers with automatic Python detection (`py` / `python3` / `python`)
- ARM64 and x86 Windows support — pure Python, zero compiled dependencies
- CLI options: `--port`, `--fragment`, `--no-doh`, `--verbose`
- Tooltip (`?`) on each GUI setting explaining purpose and tuning advice
