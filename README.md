# DokkOS

**A touch-friendly local recon console for `nmap`, Bluetooth, and Wi-Fi — one single-file Flask app behind a tactical-tablet HUD.**

DokkOS turns a Linux laptop or tablet into a tap-driven reconnaissance dashboard. It wraps tools you already use — `nmap` for host discovery and service/OS/vuln scans, BlueZ for classic + BLE device enumeration, and `airodump-ng` for Wi-Fi access-point recon — behind a single HUD inspired by the operator-tablet aesthetic of Rainbow Six Siege (original assets, no Ubisoft IP).

It's built defensively: bound to `127.0.0.1` by default, every subprocess runs as an argument list with no shell, and there is deliberately **no transmit-side attack code** (no deauth, no BLE spam). It's a recon and launcher console, not an attack framework.

> ⚠️ **Authorized use only.** Only scan or audit networks and devices you own or have explicit written permission to test. Wireless auditing against networks you don't own is illegal in most jurisdictions.

---

## Features

**Network**
- Sweep a subnet (`nmap -sn`) and list live hosts with vendor and hostname.
- Pick a host and run whitelisted scan profiles — Quick, Services, All Ports, OS, Vulnerabilities, Full Recon.
- Live streaming output with a real-time progress phase, then a parsed summary: OS fingerprint, open ports, NSE vuln findings, and de-duplicated CVEs sorted by CVSS.
- Per-port "dig deeper" with service-aware NSE script sets.

**Bluetooth**
- Streamed discovery of classic + BLE devices with live per-device recon (address type, RSSI, service UUIDs, manufacturer).
- Per-device profiles: Info, Services (`sdptool`), L2 Ping, and Vuln (via `bluing`).

**Wi-Fi**
- Monitor-mode AP recon with `airodump-ng`: BSSID, channel, encryption, signal, traffic, and associated clients.

**Console**
- One-tap launchers for interactive TUIs in their own terminal: airgeddon, wifite, bettercap, bluing, metasploit, sqlmap, nikto, hydra.
- **Stealth** toggle randomizes your MAC on scans (`nmap --spoof-mac 0`).
- **PRO / R6** views — a full live terminal, or an animated tactical call-screen.
- Settings for default view, default scan, stealth, and monitor interface (saved on-device; interface applied to the running server).

---

## Requirements

- Linux (Kali-friendly), Python 3.8+
- `flask`
- Root for OS-detection scans and all wireless tools (`sudo -E` to preserve `$DISPLAY` so terminals can open)
- Recon tools as needed: `nmap`, `bluez`, `iw`, `aircrack-ng`, `macchanger`, plus any launcher tools you want (airgeddon, wifite, bettercap, bluing, metasploit-framework, sqlmap, nikto, hydra)

---

## Install

```bash
git clone https://github.com/<you>/dokkos.git
cd dokkos
pip install flask

# check / install the recon tools (apt + pip; needs root for apt)
sudo python3 app.py --check
sudo python3 app.py --install
```

## Run

```bash
# auto-detect every network this host is on
sudo -E python3 app.py

# or pass explicit scopes (CIDR, IP, or hostname)
sudo -E python3 app.py 192.168.1.0/24 10.0.0.0/24

# then open
http://127.0.0.1:5000
```

### Options

| Flag | Description |
|------|-------------|
| `targets…` | Networks/hosts to make scannable (CIDR, IP, hostname). Default: auto-detect. |
| `--host` | Bind address. Default `127.0.0.1` — keep it local. |
| `--port` | Port. Default `5000`. |
| `--wlan-mon` | Monitor-mode interface for Wi-Fi recon (e.g. `wlan0mon`). Default: auto-detect. |
| `--check` | Report which tools are present/missing, then exit. |
| `--install` | Install missing tools (apt + pip), then continue. |

For Wi-Fi recon, put an interface into monitor mode first:

```bash
sudo airmon-ng start wlan0          # creates e.g. wlan0mon
# … later …
sudo airmon-ng stop wlan0mon && sudo systemctl restart NetworkManager
```

---

## Security model

- The browser sends **ids and validated targets only** — never command strings.
- Every subprocess runs as an **argument list with `shell=False`** — no shell, anywhere.
- Targets, MAC/BT addresses, ports, and interface names are **validated** before use, and a target can't begin with a dash, so no `nmap`-flag injection (`-oG`, etc.).
- Scan profiles, Bluetooth profiles, launcher tools, and NSE script sets are **fixed whitelists keyed by id** — no arbitrary commands or scripts can be passed.
- Output rendered in the dashboard is **HTML-escaped**, so a hostile device name or SSID can't run script in your browser.
- Bound to **`127.0.0.1`** by default. DokkOS has **no authentication** and can run scans / launch tools (often as root), so binding to any non-loopback address prints a loud warning. Don't expose it on a shared network.
- **No transmit-side attack code** — discovery, enumeration, and launching general tools only.

---

## Disclaimer

This tool is for authorized security testing and education only. You are responsible for complying with all applicable laws. The authors accept no liability for misuse or for any damage caused by this software.

## License

MIT
