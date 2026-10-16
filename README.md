# SNIper

A lightweight, zero-dependency DPI bypass proxy written in pure Python, shipped
as a portable Windows `.exe`.

It runs entirely at the **application layer**: no admin privileges, no kernel
drivers, no TAP adapters, no service installs. Just double-click the `.exe`
from any folder and it works for the current user only.

It is pre-configured and offered as a **plug-and-play** solution. All you have to do is
press the start button. You can easily monitor what is happening through a live activity log.

![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2B-blue)
![Arch](https://img.shields.io/badge/arch-x64%20%7C%20ARM64-blue)
![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![Portable](https://img.shields.io/badge/portable-no%20install-blue)

| Stopped | Running |
|:---:|:---:|
| <img src="https://github.com/user-attachments/assets/feca0063-a013-40a1-bfd4-23f61913b67b" width="380"> | <img src="https://github.com/user-attachments/assets/5b8e9473-1e6e-4872-a1c4-62e98f7b1dfb" width="380"> |

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

## How it works

ISPs block websites by inspecting the **SNI** (Server Name Indication) field inside
the TLS ClientHello. When your browser opens an HTTPS connection, the very first packet
it sends carries the target hostname in **plain text** — even though the rest of the connection is encrypted.
The ISP's DPI reads that hostname, and if it matches a blocklist, drops the connection.

SNIper handles this in **two ways**.

### ClientHello fragmentation

Instead of sending the ClientHello as a single packet,
SNIper **splits it into 2-byte** (can be changed via the GUI) TCP segments (with Nagle's algorithm disabled). That way, DPI cannot see the full hostname **in one piece**,
so it can not match the blocklist and lets the connection through. **Only the handshake (ClientHello)** is fragmented — the rest of the connection runs at **full speed.**

### DNS-over-HTTPS (DoH)

ISPs also poison DNS. When you look up a blocked domain, their resolver returns a
wrong address. SNIper sends DNS queries **over HTTPS** straight to public DNS
resolvers (Cloudflare, Google, AdGuard), which **skips** the ISP's DNS. If those are
blocked too, it falls back to plain DNS over TCP and UDP, and only uses the system
resolver as a last resort.

Everything runs as a user-space process, no admin, no kernel driver, no TAP
adapters, no service install, just a portable .exe.

---

## Features

- **User-space and portable** — no admin rights, no kernel driver, no service
  install. Just a single `.exe` you can run from anywhere, even a USB stick.
- **Plug-and-play** — zero configuration. Press **Start** and you are done.
- **Native x64 and ARM64 builds** — unlike most DPI bypass tools, it runs natively on ARM64 Windows.
- **Fragmentation + DNS-over-HTTPS (DoH) together** — bypasses both SNI-based blocking and DNS poisoning
  in one tool, which covers most ISP-level filtering.
- **Your internet never breaks because of SNIper** — by default, apps fall back
  to a direct connection on their own as soon as SNIper is gone. A safety guard
  restores your settings the moment SNIper closes unexpectedly, and Windows
  sign-out, restart and shutdown are handled too.
- **Smart DNS chain** — DoH → UDP → TCP → system DNS, so name resolution keeps working even on hostile networks.

---

## Usage

Download `SNIper_<arch>.exe` and double-click it.
Press **Start** to turn the proxy on; SNIper sets the Windows system proxy automatically, so
Chrome, Spotify, Steam and most other apps route through it right away. Press **Stop** or close
the window to turn it off and restore your previous proxy settings.

You can minimize it to the system tray and control it from there. Settings are locked while the proxy is running.
Tick **Remember settings** to keep them for the next launch: they are stored for your Windows user only, nothing is written next to the EXE, and unticking the box forgets them.

### Settings

| Setting | Default | What it does |
|---|---|---|
| Port | 8881 | Local port the proxy listens on |
| Fragment size | 2 | Bytes per TCP segment during the TLS handshake |
| Disable DoH | off | Use system DNS instead of DNS-over-HTTPS |
| Verbose | off | Show detailed debug messages in the log |
| Compatibility mode | off | Use a fixed system proxy, for apps that don't go through SNIper in safe mode |
| Remember settings | off | Keep your settings for the next launch |

---

## Under the hood

A few details that were trickier than they look:

- **Hand-driven TLS handshake.** Python's `urllib` sends the ClientHello in one
  TCP segment, which defeats fragmentation. The DoH client drives the TLS
  handshake manually through memory BIOs so its own ClientHello is fragmented
  too — otherwise DoH itself gets blocked the same way.
- **Fail-open auto-config script.** In the default safe mode, SNIper points
  Windows at a small auto-config (PAC) script that it serves itself, which says
  `PROXY 127.0.0.1:<port>; DIRECT`: use SNIper, or go direct if it doesn't
  answer. Next to it SNIper sets a manual proxy whose bypass list is every host
  (`ProxyOverride="*"`). Once SNIper is gone, the script can't be fetched and the
  proxy refuses connections, so apps connect directly; Windows and Chrome fall
  back from a failed script to the manual proxy, and its bypass list sends every
  host direct as well. The manual proxy is there for apps that read nothing but
  the fixed proxy, such as the Discord desktop app's updater. Each session's
  script has its own random URL, so apps notice the change at once and SNIper
  can tell exactly which setting is its own.
- **Safety guard process.** Your original proxy settings are saved to the registry
  before anything changes. When SNIper applies the proxy, it also starts a small
  separate process that waits, using no CPU, for SNIper to end. If SNIper is
  killed or crashes, the guard puts your settings back at once and shows a
  notification. It only ever touches its own session's settings, and it leaves
  quietly when SNIper stops normally. It is started through a short-lived helper,
  so ending SNIper's process tree doesn't take it down.
- **Session end.** A hidden window receives Windows' sign-out, restart and
  shutdown messages and restores the proxy right there, before Windows may end
  the process. SNIper also asks Windows to notify it among the first apps, so a
  hung app can't force a "Shut down anyway" before SNIper has restored.
- **Authoritative vs. spoofed DNS negatives.** A "host doesn't exist" answer is
  trusted only over verified DoH; the same answer over plain UDP is treated as a
  possible injection and ignored, so a poisoning ISP can't shut down a lookup.

---

## Limitations

SNIper bypasses SNI-based filtering only — it does not encrypt traffic or hide
your IP. A few cases where it won't help:

- **Firefox** uses its own proxy and DNS settings, so SNIper has no effect until
  you point Firefox at the system proxy.
- **Antivirus HTTPS scanning** (ESET, Kaspersky, Bitdefender, etc.) reassembles
  the fragmented ClientHello before it leaves your machine, which re-exposes the
  SNI. Disable HTTPS/TLS scanning if blocked sites stay blocked.
- **Active VPNs** route traffic through their own adapter and may bypass the
  system proxy entirely.
- **HTTP/3 (QUIC)** runs over UDP, which the TCP proxy can't carry. Browsers fall
  back to TCP within a second or two, so most sites still load.
- **Apps that read only the fixed proxy**, such as the Discord desktop app, read
  it once when they start: restart one that was already open when you pressed
  Start. They are the exception to safe mode's fail-open: if SNIper and its
  safety guard are both gone (a power loss, both ended), they can't connect until
  you open SNIper again, which puts your settings back.
- **In Compatibility mode, after a power loss** (or if SNIper and its safety
  guard are both ended), your proxy settings are restored at the next sign-in
  by a one-time Windows startup entry. A console window may flash briefly when
  it runs. SNIper removes the entry again on every clean exit.
- **While SNIper runs**, the Windows proxy settings show "Use setup script" and
  "Use a proxy server", both with a `127.0.0.1` address (the proxy server's
  exceptions are `*`), and Task Manager may show a second SNIper background
  process: the safety guard.

---

## Building from source

```packaging\build_exe.bat```

Installs PyInstaller (6.9 or a later 6.x) if needed, builds a single-file
`SNIper_<arch>.exe` at the project root, verifies its PE architecture, and prints
its SHA-256. PyInstaller doesn't cross-compile, so x64 and ARM64 each need a
native build.

To run without building: `python src/run_sniper.py` (Python 3.7+). The EXE itself
needs Windows 10 1607 or later (x64 or ARM64) and bundles its own runtime.

---

## Disclaimer

Published for educational and personal use, to help access content that is
legally available to you but blocked by ISP-level filtering. Use it in accordance
with your local laws. SNIper does not encrypt traffic or provide anonymity — it
only bypasses SNI-based filtering, and your existing TLS encryption stays intact
end-to-end.
