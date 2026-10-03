# Changelog

## v1.1.6 - 2026-07-04

A fix for computers without working IPv6.

- **No more false "No internet" warning.** On machines without IPv6 connectivity, Windows could mark the connection as offline while SNIper was running, because its own IPv6 connection check failed through the proxy. SNIper now gives Windows the same answer it would get without the proxy, so the network icon stays correct.
- **Smarter address choice.** When a site offers both IPv4 and IPv6 addresses, SNIper now only picks one your network can actually reach. Sites that offer only IPv6 fail quickly with a clear message instead of a confusing error.
- **Clear errors for plain HTTP sites.** If an unencrypted (http://) site can't be reached, your app now receives a proper "Bad Gateway" error instead of a connection that silently closes.

IPv6 still works normally on networks that support it, and DNS protection is unchanged.

---

## v1.1.5 - 2026-06-17

SNIper now makes sure your proxy settings are never left broken, even after a crash.

Previously, if SNIper closed unexpectedly (force-closed from Task Manager, a power cut, or Windows shutting down), your system proxy could stay pointed at SNIper after it was gone, leaving apps without internet. In some cases a later restart could even overwrite your original proxy settings for good.

- **Your settings are saved safely.** Before changing anything, SNIper stores your original proxy settings in the registry, so they survive a crash or power loss.
- **Automatic recovery on launch.** If SNIper finds settings left behind by an unexpected exit, it restores them as soon as you open the app. You don't even need to press Start.
- **Your original settings are never lost.** SNIper can tell its own settings apart from yours, so no number of crashes and restarts can overwrite your real configuration.
- **Clean exit, no leftovers.** When SNIper stops, all proxy settings (including auto-config scripts) go back exactly as they were and take effect immediately.

Closing the window or pressing Stop still restores your settings right away. On company-managed computers where proxy settings are locked by policy, SNIper still changes nothing and shows a warning.

Behind the scenes, the code was reorganized and the separate command-line version was removed. SNIper is now GUI-only, as it has always been shipped. How the app works is unchanged.

---

## v1.1.4 - 2026-06-12

Much faster handling of addresses that don't exist.

Apps and websites often try to reach servers that no longer exist, such as retired tracking servers, removed download mirrors or simple typos. SNIper used to spend about 6 seconds trying every fallback before giving up on each one. Now it recognizes them almost instantly.

- **Instant answers for non-existent sites.** When a secure DNS server confirms that a name doesn't exist, SNIper stops right away and logs a single clear line ("host does not exist") instead of a wall of warnings.
- **Still protected against fake answers.** "Does not exist" replies over regular, unencrypted DNS are still ignored, because an ISP could fake them to block a site. Only verified secure DNS answers are trusted.
- **Remembered failures.** Names that don't exist are remembered for a short while, so repeated requests fail instantly.
- **Time limit for lookups.** Every lookup now finishes within 3 seconds, so a slow or blocked DNS server can't hold things up.
- **Less noise on IPv4-only networks.** SNIper no longer tries DNS servers your network can't reach, which cuts delays and log clutter.

Unblocking real sites works exactly as before. The activity log shows the new results in plain language, with more detail in Verbose mode.

---

## v1.1.3 - 2026-05-22

A compatibility release to help SNIper start and work reliably on as many computers and networks as possible.

**Windows and display**
- Windows 7 and 8 were wrongly listed as supported. The real minimum, Windows 10 version 1607, is now clearly stated.
- The window stays sharp when moved between monitors with different scaling, and fits on small screens.
- The log panel uses a proper fixed-width font on Windows 10 too.
- The tray icon comes back on its own if Windows Explorer restarts.
- SNIper now has its own icon in the taskbar, title bar, Alt-Tab and tray.

**Networks**
- Works on IPv6-only networks, used by some mobile and fiber providers.
- More DNS providers (AdGuard, DNS.SB), so if one is blocked another takes over quickly.
- A clear warning when your secure connections are being intercepted by software or a device on your network.
- IPv6 addresses typed directly into the browser now work.

**Stability**
- Other programs can no longer take over SNIper's port.
- A sudden burst of connections can no longer crash the app.
- Connections dropped by sleep or a Wi-Fi change are cleaned up instead of piling up.
- Opening SNIper twice shows a clear message instead of two copies conflicting.

**Company networks**
- If proxy settings are locked by Group Policy, SNIper warns you instead of failing silently.
- If an auto-config (PAC) script is in use, SNIper pauses it while running and restores it on exit.

**Other**
- The README now covers system requirements, known limitations and antivirus or SmartScreen warnings.

---

## v1.1.2 - 2026-05-15

Secure DNS now works on networks that actively block or tamper with it.

Testing on heavily filtered networks showed that secure DNS (DoH) could fail completely, pushing every lookup onto regular DNS, which ISPs manipulate for blocked sites. This release fixes that.

- **Harder to detect.** SNIper now splits its own secure DNS connections into small pieces, the same trick it uses for your browser traffic, so the ISP can't spot and block them.
- **Works with more providers.** SNIper now uses the standard secure DNS format that every provider supports, instead of one that only Cloudflare fully accepted.
- **Better server list.** Quad9 was removed because it doesn't work with SNIper, and AdGuard and DNS.SB were added. If one provider is blocked or tampered with, SNIper moves on to the next in under a second.
- **New fallback.** If regular DNS replies are being altered, SNIper also tries DNS over TCP, which many networks leave untouched.

The project is now called **SNIper**. The app file is now `SNIper_<arch>.exe` (previously `DPI_Bypass_Proxy_<arch>.exe`), and the window title and tray icon use the new name.

---

## v1.1.1 - 2026-05-11

Name lookups now keep working when secure DNS is blocked, and IPv6-only sites are supported.

- **New fallback when secure DNS is blocked.** On some networks every secure DNS server is blocked. SNIper used to fall back to your ISP's DNS, which can return wrong addresses for blocked sites like Discord. It now asks public DNS servers (Cloudflare, Google and others) directly first, which ISPs usually leave alone.
- **IPv6-only sites.** Some addresses, such as Windows' own IPv6 connection check, exist only on IPv6. SNIper can now find and connect to them, while still preferring IPv4 whenever it's available.
- **Better last resort.** The final fallback, your system DNS, now finds IPv6 addresses too, including when DoH is turned off.
- **Clearer log.** The activity log now shows how each address was found, for example "Resolved X via public DNS".

The "Disable DoH" tooltip now explains that turning it off also turns off the public DNS fallback.

---

## v1.1.0 - 2026-05-10

SNIper is now a single portable app. No Python installation needed.

- **One-file app.** Everything comes in a single .exe. There are separate builds for x64 and ARM64 computers, and the old .bat launchers are gone.
- **System tray.** When minimized, SNIper moves to the system tray. Right-click the icon for quick controls that change depending on whether the proxy is running.
- **Refreshed look.** The interface has a cleaner style and stays sharp on high-resolution displays instead of looking blurry.
- **Smarter DNS memory.** SNIper remembers up to 1024 recent addresses and keeps the ones you use most, so sites you visit often open faster.
- **More reliable secure DNS.** Fixed an issue where some DNS servers rejected SNIper's requests.
- **Fewer connection errors.** Some websites failed to load because certain connection details were passed along when they shouldn't have been. These are now removed before forwarding.
- Several small fixes for rare errors.

---

## v1.0.0 - 2026-05-05

First release, originally named DPI Bypass Proxy.

- **Bypasses SNI-based blocking** by splitting the start of each secure connection into tiny pieces, so your ISP's filter can't read which site you're visiting.
- **Secure DNS (DNS-over-HTTPS)** through Cloudflare and Google, so your ISP can't send blocked sites to the wrong address. Results are remembered for faster repeat visits.
- **Automatic setup.** Sets the Windows system proxy for you when started and removes it when stopped.
- **Simple window** to start and stop the proxy and follow the activity log, plus a command-line version for advanced users.