<div align="center">

# 🎯 SNIper

**A lightweight, zero-dependency DPI bypass proxy written in pure Python, shipped as a portable Windows `.exe`.**

![Platform](https://img.shields.io/badge/platform-Windows%2010%2B-blue?style=flat-square)
![Arch](https://img.shields.io/badge/arch-x64%20%7C%20ARM64-blue?style=flat-square)
![Python](https://img.shields.io/badge/python-3.7%2B-blue?style=flat-square&logo=python&logoColor=white)
![Portable](https://img.shields.io/badge/portable-no%20install-blue?style=flat-square)

</div>

<br>

SNIper runs entirely at the **application layer** — no admin privileges, no kernel drivers, no TAP adapters, no service installs. Just double-click the `.exe` from any folder and it works for the current user only.

It comes **pre-configured** as a **plug-and-play** solution: all you have to do is press **Start**. A live activity log lets you follow everything that's happening.

<div align="center">

| ⏹️ Stopped | ▶️ Running |
|:---:|:---:|
| <img src="https://github.com/user-attachments/assets/361004f3-7d8a-471d-a8f2-44b1a2de8bf1" width="380"> | <img src="https://github.com/user-attachments/assets/7244f5c5-7fce-42ef-9c99-bd090f1ec1e5" width="380"> |

</div>

## 🌱 Origin

This project started from a personal need. I have an **ARM64 Windows** machine and couldn't find a working, pre-built DPI bypass tool for that architecture. Most existing solutions ship compiled binaries, none of them ran natively on ARM64, and most of them required admin rights or driver installs.

So I described the problem to **Claude** and asked it to write one from scratch in **pure Python**, which has no architecture dependency and runs entirely in user-space. After many rounds of feeding errors back and refining, this is the result, and it is still being developed. I do a lot of testing and read detailed logs to improve the stability and compatibility of the code.

> 💬 *I'm publishing it in case anyone else runs into the same gap.*

## 💡 How it works

ISPs block websites by reading the **SNI** (Server Name Indication): the name of the site you're visiting, which your browser sends in **plain text** in the very first message of every HTTPS connection (the TLS *ClientHello*), before encryption kicks in. If that name is on a blocklist, the connection is dropped.

SNIper gets around this in **two ways**:

### 🧩 Splitting the handshake

SNIper sends that first message in **tiny pieces** (2 bytes each by default, adjustable in the app). The filter never sees the full site name in one piece, so it can't match it against the blocklist and lets the connection through. Only the handshake is split — the rest of the connection runs at **full speed**.

### 🔒 Secure DNS (DoH)

ISPs also poison DNS, handing out wrong addresses for blocked sites. SNIper skips your ISP's DNS and asks public resolvers (Cloudflare, Google, AdGuard) over an encrypted **DNS-over-HTTPS** connection. If those are blocked too, it automatically falls back to other public DNS routes, and uses your system DNS only as a last resort.

## ✨ Features

- ▶️ **Plug-and-play** — nothing to set up or configure. Press **Start** and you're done.
- 💼 **Portable, no install** — a single `.exe` you can run from any folder, even a USB stick. No admin rights needed, and nothing gets installed on your PC.
- 💻 **Native x64 and ARM64 builds** — unlike most DPI bypass tools, it runs natively on ARM64 Windows.
- 🔓 **Opens blocked sites** — gets past the two most common ways ISPs block websites (reading the site's name and handing out fake addresses), which covers most ISP-level filtering.
- 🌐 **Works with the apps you use** — SNIper sets up Windows for you, so Chrome, Spotify, Steam, Discord and most other apps go through it automatically.
- 🛡️ **Your internet never breaks because of SNIper** — by default, apps fall back to a direct connection on their own as soon as SNIper is gone. A safety guard restores your settings the moment SNIper closes unexpectedly, and Windows sign-out, restart and shutdown are handled too.
- 🔁 **Keeps working on tough networks** — if one secure DNS service is blocked, SNIper quietly moves on to the next, so sites keep loading even on heavily filtered networks.

## 🚀 Usage

1. **Download** `SNIper_<arch>.exe` (`x64` or `ARM64`, matching your PC) from [Releases](https://github.com/Reuzola/SNIper/releases) and double-click it.
2. **Press Start** to turn the proxy on. SNIper sets the Windows system proxy automatically, so Chrome, Spotify, Steam and most other apps route through it right away.
3. **Press Stop** or close the window to turn it off and restore your previous proxy settings.

<sub>🪟 Requires Windows 10 (version 1607) or later. No Python needed: the `.exe` bundles its own runtime.</sub>

> [!TIP]
> - 🗂️ **System tray:** minimize SNIper to the tray and control it from there. Settings are locked while the proxy is running.
> - 💾 **Remember settings:** tick it to keep your settings for the next launch. They're stored for your Windows user only, nothing is written next to the EXE, and unticking the box forgets them.

### 🔧 Settings

| Setting | Default | What it does |
|---|:---:|---|
| 🔌 **Port** | `8881` | Local port the proxy listens on |
| ✂️ **Fragment size** | `2` | Bytes per TCP segment during the TLS handshake |
| 🌐 **Disable DoH** | off | Use system DNS instead of DNS-over-HTTPS |
| 📝 **Verbose** | off | Show detailed debug messages in the log |
| 🧰 **Compatibility mode** | off | Use a fixed system proxy, for apps that don't go through SNIper in safe mode |
| 💾 **Remember settings** | off | Keep your settings for the next launch |

## 🚧 Limitations

SNIper only gets around SNI-based blocking — it doesn't encrypt your traffic or hide your IP. It may not help in these cases:

- 🦊 **Firefox** may use its own proxy settings. If blocked sites don't open there, switch it to *Use system proxy settings*.
- 🛡️ **Antivirus HTTPS scanning** (ESET, Kaspersky, Bitdefender…) can undo SNIper's work. If sites stay blocked, turn it off.
- 🔐 **VPNs** may route your traffic around SNIper entirely.
- 🐢 **HTTP/3 (QUIC)** can't go through SNIper, but browsers fall back to a regular connection within seconds.
- 🎮 **Discord** and similar apps read the proxy only at startup: restart them if they were open when you pressed **Start**. If the PC loses power while SNIper runs, they stay offline until you open SNIper again.
- 🧰 **Compatibility mode:** after a power loss, your settings are restored at the next sign-in (a console window may flash briefly).

> [!NOTE]
> **Totally normal:** while SNIper runs, Windows proxy settings show `127.0.0.1` entries and Task Manager may list a second SNIper process (the safety guard). The `.exe` isn't code-signed, so SmartScreen may warn you on first launch.

## 🔬 Under the hood

A few details that were trickier than they look:

- **Hand-driven TLS for DoH.** `urllib` sends the ClientHello in one TCP segment, which would get DoH itself blocked, so the DoH client drives the handshake through memory BIOs and fragments its own ClientHello too.
- **Fail-open PAC script.** Safe mode points Windows at a PAC script SNIper serves itself (`PROXY 127.0.0.1:<port>; DIRECT`), plus a manual proxy with `ProxyOverride="*"` for apps that read nothing else, like Discord's updater. Once SNIper is gone, the script can't be fetched, and Windows and Chrome fall back to the manual proxy, whose bypass list sends every host direct. The script gets a random URL per session, so SNIper always knows which setting is its own.
- **Safety guard process.** The original settings are saved to the registry before anything changes. A separate idle process, launched via a short-lived helper so ending SNIper's process tree doesn't take it down, restores its own session's settings if SNIper is killed or crashes.
- **Session end.** A hidden window catches sign-out, restart and shutdown messages and restores the proxy right there. SNIper asks to be notified among the first apps, so a hung app can't force "Shut down anyway" before that.
- **Trusted vs. spoofed DNS negatives.** "Host doesn't exist" is trusted only over verified DoH; over plain UDP it's treated as a possible injection and ignored.

### 📦 Building from source

Run `packaging\build_exe.bat` on an x64 or ARM64 machine to build `SNIper_<arch>.exe` for that architecture. To run without building: `python src/run_sniper.py` (Python 3.7+).

## 📜 Disclaimer

> [!IMPORTANT]
> Published for educational and personal use, to help access content that is legally available to you but blocked by ISP-level filtering. Use it in accordance with your local laws. SNIper does not encrypt traffic or provide anonymity — it only bypasses SNI-based filtering, and your existing TLS encryption stays intact end-to-end.

<div align="center">
<br>
<sub>Released under the <a href="LICENSE">MIT License</a>.</sub>
</div>