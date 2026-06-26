#!/usr/bin/env python3
"""
DokkOS  —  interactive local recon console.

A Flask app serving a touch HUD that:
  * discovers live hosts with `nmap -sn` and lists them,
  * lets you select a host and run whitelisted nmap scans with live output,
  * launches interactive security tools (airgeddon, wifite, bettercap) in a
    real terminal window, because those are ncurses TUIs that can't be driven
    from a streamed <pre>.

SECURITY MODEL (unchanged from v1):
  * The browser sends *ids* (scan profile id, tool id) — never command strings.
  * The only free text is the target/subnet, validated as IP/CIDR/hostname
    before it ever reaches a subprocess.
  * subprocess always runs with an argument LIST and shell=False. No shell.
  * Bound to 127.0.0.1 only.

  Only scan / audit networks you own or are explicitly authorised to test.
  Wireless auditing tools are illegal to use against networks you don't own.

Run (root needed for OS-detection scans and the wireless tools):
  pip install flask
  sudo -E python3 app.py        # -E preserves DISPLAY so terminals can open
  open http://127.0.0.1:5000
"""

import argparse
import glob
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import xml.etree.ElementTree as ET

from flask import Flask, Response, jsonify, request, stream_with_context

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Whitelisted nmap scan profiles. id -> fixed argument list. Target appended.
# ---------------------------------------------------------------------------
SCAN_PROFILES = {
    "quick":    {"label": "Quick Scan",
                 "args": ["-v", "-F", "-T4"], "root": False},
    "services": {"label": "Services + Ports",
                 "args": ["-v", "-sV", "-O", "--osscan-guess", "-T4"], "root": True},
    "full":     {"label": "All Ports",
                 "args": ["-v", "-sV", "-O", "--osscan-guess", "-p-", "-T4",
                          "--host-timeout", "25m"], "root": True},
    "os":       {"label": "OS + Services",
                 "args": ["-v", "-sV", "-O", "--osscan-guess", "-T4"], "root": True},
    "vuln":     {"label": "Vulnerabilities",
                 "args": ["-v", "-sV", "-O", "--osscan-guess",
                          "--script", "vuln,vulners", "-T4"], "root": True},
    "deep":     {"label": "Full Recon",
                 "args": ["-v", "-sV", "-O", "--osscan-guess",
                          "--script", "vuln,vulners", "-T4"], "root": True},
}
DEFAULT_PROFILE = "deep"

# Service-aware NSE script sets for the per-port "dig deeper" action. The browser
# sends a service *name*; we look it up here (fixed map) so no arbitrary scripts
# can be injected. Unknown services fall back to the generic set.
SERVICE_SCRIPTS = {
    "http":          "http-title,http-headers,http-methods,http-enum,vulners",
    "https":         "http-title,http-headers,ssl-enum-ciphers,ssl-cert,vulners",
    "ssl":           "ssl-enum-ciphers,ssl-cert,vulners",
    "ssh":           "ssh2-enum-algos,ssh-auth-methods,vulners",
    "ftp":           "ftp-anon,ftp-syst,vulners",
    "smb":           "smb-os-discovery,smb-security-mode,smb-protocols,smb-vuln-*",
    "microsoft-ds":  "smb-os-discovery,smb-security-mode,smb-protocols,smb-vuln-*",
    "netbios-ssn":   "smb-os-discovery,smb-protocols,smb-vuln-*",
    "mysql":         "mysql-info,mysql-empty-password,vulners",
    "ms-sql-s":      "ms-sql-info,ms-sql-ntlm-info",
    "rdp":           "rdp-ntlm-info,rdp-enum-encryption",
    "ms-wbt-server": "rdp-ntlm-info,rdp-enum-encryption",
    "dns":           "dns-nsid,dns-recursion",
    "domain":        "dns-nsid,dns-recursion",
    "smtp":          "smtp-commands,smtp-open-relay,vulners",
    "snmp":          "snmp-info,snmp-sysdescr",
    "telnet":        "telnet-encryption,vulners",
    "vnc":           "vnc-info,vnc-title",
    "redis":         "redis-info",
    "mongodb":       "mongodb-info",
}
DEFAULT_PORT_SCRIPTS = "default,vuln,vulners"

# ---------------------------------------------------------------------------
# Dependencies. Maps a command -> how to install it. Used by --install / --check
# so a fresh box can be set up in one go (needs root for apt).
# ---------------------------------------------------------------------------
DEPENDENCIES = {
    "nmap":         ("apt", "nmap"),
    "bluetoothctl": ("apt", "bluez"),
    "sdptool":      ("apt", "bluez"),
    "l2ping":       ("apt", "bluez"),
    "iw":           ("apt", "iw"),
    "airodump-ng":  ("apt", "aircrack-ng"),
    "macchanger":   ("apt", "macchanger"),
    "airgeddon":    ("apt", "airgeddon"),
    "wifite":       ("apt", "wifite"),
    "bettercap":    ("apt", "bettercap"),
    "bluing":       ("pip", "bluing"),
    "msfconsole":   ("apt", "metasploit-framework"),
    "sqlmap":       ("apt", "sqlmap"),
    "nikto":        ("apt", "nikto"),
    "hydra":        ("apt", "hydra"),
}


def check_dependencies():
    """Return (present, missing_apt_pkgs, missing_pip_pkgs)."""
    present, apt_pkgs, pip_pkgs = [], [], []
    for tool, (kind, pkg) in DEPENDENCIES.items():
        if shutil.which(tool):
            present.append(tool)
        elif kind == "apt":
            if pkg not in apt_pkgs:
                apt_pkgs.append(pkg)
        else:
            if pkg not in pip_pkgs:
                pip_pkgs.append(pkg)
    return present, apt_pkgs, pip_pkgs


def install_dependencies():
    """Install missing apt + pip packages. Requires root for apt."""
    _, apt_pkgs, pip_pkgs = check_dependencies()
    if not apt_pkgs and not pip_pkgs:
        print("[install] all dependencies already present.")
        return
    if apt_pkgs:
        if os.geteuid() != 0:
            print("[install] apt packages need root — re-run with sudo:", " ".join(apt_pkgs))
        else:
            print("[install] apt-get install:", " ".join(apt_pkgs))
            subprocess.run(["apt-get", "update"], check=False)
            subprocess.run(["apt-get", "install", "-y"] + apt_pkgs, check=False)
    if pip_pkgs:
        print("[install] pip install:", " ".join(pip_pkgs))
        subprocess.run(["pip", "install", "--break-system-packages"] + pip_pkgs, check=False)


def stealth_prefix(data):
    """nmap flags to randomise our own MAC when the Stealth toggle is on."""
    return ["--spoof-mac", "0"] if (data or {}).get("stealth") else []


# ---------------------------------------------------------------------------
# Whitelisted interactive tools. Launched in a real terminal window.
# These are TUIs (menus / live capture), so they get their own terminal,
# not the in-browser output pane.
# ---------------------------------------------------------------------------
TOOLS = {
    "airgeddon":  {"label": "airgeddon",  "cmd": ["airgeddon"]},
    "wifite":     {"label": "wifite",     "cmd": ["wifite"]},
    "bettercap":  {"label": "bettercap",  "cmd": ["bettercap"]},
    "bluing":     {"label": "bluing",     "cmd": ["bluing"]},
    "metasploit": {"label": "metasploit", "cmd": ["msfconsole"]},
    "sqlmap":     {"label": "sqlmap",     "cmd": ["sqlmap", "--wizard"]},
    "nikto":      {"label": "nikto",      "cmd": ["nikto"]},
    "hydra":      {"label": "hydra",      "cmd": ["hydra"]},
}
# Map launch ids whose binary differs from the id (for the install check).
TOOL_BIN = {"metasploit": "msfconsole"}

# Whitelisted Bluetooth scan profiles. Each maps id -> fixed command prefix; the
# validated MAC is appended. These cover classic + BLE enumeration with BlueZ.
# "vuln" uses bluing (a dedicated BT recon/vuln tool) if installed.
BT_PROFILES = {
    "info":     {"label": "Info",     "cmd": ["bluetoothctl", "info"], "root": False},
    "services": {"label": "Services", "cmd": ["sdptool", "browse"],    "root": True},
    "ping":     {"label": "L2 Ping",  "cmd": ["l2ping", "-c", "5"],    "root": True},
    "vuln":     {"label": "Vuln",     "cmd": ["bluing", "br", "--sdp"],"root": True},
}

# Terminal emulators tried in order. Edit if yours isn't here.
TERMINAL_CANDIDATES = [
    ["x-terminal-emulator", "-e"],
    ["xterm", "-e"],
    ["qterminal", "-e"],
    ["konsole", "-e"],
    ["xfce4-terminal", "-x"],
]

HARD_TIMEOUT_SECONDS = 30 * 60
DISCOVERY_TIMEOUT_SECONDS = 180

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def validate_target(raw):
    """Return cleaned target (IP / CIDR / hostname) or None."""
    if raw is None:
        return None
    t = raw.strip()
    if not t or len(t) > 255:
        return None
    try:
        ipaddress.ip_network(t, strict=False)
        return t
    except ValueError:
        pass
    return t if _HOSTNAME_RE.match(t) else None


_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def validate_mac(raw):
    """Return an uppercase MAC/BT address, or None."""
    if raw is None:
        return None
    m = raw.strip().upper()
    return m if _MAC_RE.match(m) else None


def parse_bt_devices(text):
    """Parse `bluetoothctl devices` output: lines like 'Device AA:.. Name'."""
    devs = []
    for line in (text or "").splitlines():
        mobj = re.search(r"Device\s+([0-9A-Fa-f:]{17})\s*(.*)", line)
        if mobj:
            devs.append({"mac": mobj.group(1).upper(), "name": mobj.group(2).strip() or None})
    return devs


def parse_bt_info(text):
    """Parse `bluetoothctl info MAC` into BLE recon fields."""
    info = {"type": None, "rssi": None, "name": None,
            "connected": None, "uuids": [], "manufacturer": None}
    for line in (text or "").splitlines():
        s = line.strip()
        mh = re.match(r"Device\s+[0-9A-Fa-f:]{17}\s+\((public|random)\)", s)
        if mh:
            info["type"] = mh.group(1)
            continue
        if s.startswith("Name:"):
            info["name"] = s.split(":", 1)[1].strip()
        elif s.startswith("RSSI:"):
            info["rssi"] = s.split(":", 1)[1].strip()
        elif s.startswith("Connected:"):
            info["connected"] = s.split(":", 1)[1].strip()
        elif s.startswith("UUID:"):
            mu = re.search(r"UUID:\s*(.+?)\s*\(", s)
            if mu:
                info["uuids"].append(mu.group(1).strip())
        elif s.startswith("ManufacturerData Key:"):
            info["manufacturer"] = s.split(":", 1)[1].strip()
    return info


def validate_port(raw):
    """Return an int port 1-65535, or None."""
    try:
        p = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return p if 1 <= p <= 65535 else None


def detect_monitor_iface():
    """Return the first wireless interface in monitor mode, or None."""
    try:
        out = subprocess.run(["iw", "dev"], stdout=subprocess.PIPE, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    iface = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            iface = line.split(None, 1)[1]
        elif line.startswith("type ") and "monitor" in line and iface:
            return iface
    return None


def parse_airodump_csv(text):
    """Parse airodump-ng CSV into access points and associated clients."""
    aps, clients = [], []
    section = 0
    mac_re = re.compile(r"^[0-9A-Fa-f:]{17}$")
    for line in (text or "").splitlines():
        st = line.strip()
        if st.startswith("BSSID,"):
            section = 1
            continue
        if st.startswith("Station MAC,"):
            section = 2
            continue
        if not st:
            continue
        cols = [c.strip() for c in line.split(",")]
        if section == 1 and len(cols) >= 14 and mac_re.match(cols[0]):
            aps.append({
                "bssid": cols[0], "channel": cols[3],
                "enc": (cols[5] + " " + cols[6]).strip(),
                "power": cols[8], "beacons": cols[9], "data": cols[10],
                "essid": cols[13] or "<hidden>",
            })
        elif section == 2 and len(cols) >= 6 and mac_re.match(cols[0]):
            clients.append({
                "station": cols[0], "power": cols[3],
                "packets": cols[4], "bssid": cols[5],
            })
    return {"aps": aps, "clients": clients}


def find_terminal():
    for cand in TERMINAL_CANDIDATES:
        if shutil.which(cand[0]):
            return cand
    return None


# Networks the discovery sweep is allowed to scan. Set at startup from CLI args
# (or auto-detected). The browser can only pick from this list — it can't inject
# an arbitrary range.
SCAN_TARGETS = []

# Monitor-mode interface for Wi-Fi recon (set via --wlan-mon, or auto-detected).
WIFI_MON = None


def detect_local_networks():
    """Return CIDRs for every globally-scoped IPv4 the host is attached to."""
    nets = []
    try:
        out = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "scope", "global"],
            stdout=subprocess.PIPE, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return nets
    for line in out.splitlines():
        mobj = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
        if not mobj:
            continue
        try:
            cidr = str(ipaddress.ip_network(mobj.group(1), strict=False))
        except ValueError:
            continue
        if cidr not in nets:
            nets.append(cidr)
    return nets


def get_scan_targets():
    """Configured targets, or a lazy auto-detect fallback if launched without."""
    if SCAN_TARGETS:
        return SCAN_TARGETS
    return detect_local_networks() or ["192.168.1.0/24"]


def parse_discovery(xml_text):
    """Parse `nmap -sn -oX -` output into a list of host dicts."""
    hosts = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts
    for h in root.findall("host"):
        status = h.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = vendor = name = None
        for addr in h.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            name = hn.get("name")
        if ip:
            hosts.append({"ip": ip, "mac": mac, "vendor": vendor, "name": name})
    return hosts


def run_capture(cmd, timeout):
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=timeout,
    )
    return proc.stdout, proc.stderr, proc.returncode


def _is_real_finding(txt):
    """True unless the NSE output is just a script-execution error (not a real vuln)."""
    t = (txt or "").strip()
    if "VULNERABLE" in t:
        return True
    low = t.lower()
    if t.startswith("ERROR:") or "script execution failed" in low \
       or "could not" in low or "couldn't" in low:
        return False
    return True


def parse_scan_xml(path):
    """Parse an nmap XML result into hosts with ports, services, OS, vulns."""
    out = {"hosts": []}
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, FileNotFoundError, OSError):
        return out
    for h in root.findall("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        info = {"ip": None, "name": None, "vendor": None,
                "os": None, "os_detail": None, "os_guesses": [],
                "ports": [], "vulns": []}
        for addr in h.findall("address"):
            if addr.get("addrtype") == "ipv4":
                info["ip"] = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                info["vendor"] = addr.get("vendor")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            info["name"] = hn.get("name")
        osnode = h.find("os")
        if osnode is not None:
            matches = osnode.findall("osmatch")
            if matches:
                best = matches[0]
                info["os"] = f'{best.get("name")} ({best.get("accuracy")}%)'
                cls = best.find("osclass")
                if cls is None:
                    cls = osnode.find("osclass")
                if cls is not None:
                    bits = []
                    for attr, lbl in (("type", "type"), ("vendor", "vendor"),
                                      ("osfamily", "family"), ("osgen", "gen")):
                        if cls.get(attr):
                            bits.append(f"{lbl} {cls.get(attr)}")
                    info["os_detail"] = " · ".join(bits) or None
                try:
                    top_acc = int(best.get("accuracy", "0"))
                except ValueError:
                    top_acc = 0
                if len(matches) > 1 and top_acc < 97:
                    info["os_guesses"] = [
                        f'{mm.get("name")} ({mm.get("accuracy")}%)'
                        for mm in matches[1:4]
                    ]
        for p in h.findall("ports/port"):
            pst = p.find("state")
            if pst is None or pst.get("state") != "open":
                continue
            svc = p.find("service")
            product = ""
            if svc is not None:
                product = " ".join(filter(None, [svc.get("product"),
                                                 svc.get("version")])).strip()
            info["ports"].append({
                "port": p.get("portid"), "proto": p.get("protocol"),
                "service": (svc.get("name") if svc is not None else ""),
                "product": product,
            })
            for sc in p.findall("script"):
                sid, txt = sc.get("id", ""), (sc.get("output") or "")
                if ("vuln" in sid or "VULNERABLE" in txt) and _is_real_finding(txt):
                    info["vulns"].append((f'{p.get("portid")}/{sid}', txt.strip()))
        for sc in h.findall("hostscript/script"):
            sid, txt = sc.get("id", ""), (sc.get("output") or "")
            if ("vuln" in sid or "VULNERABLE" in txt) and _is_real_finding(txt):
                info["vulns"].append((sid, txt.strip()))
        out["hosts"].append(info)
    return out


def format_summary(path):
    data = parse_scan_xml(path)
    if not data["hosts"]:
        return "\n[no summary — host appears down or scan was interrupted]\n"
    lines = ["", "=" * 50, "SUMMARY", "=" * 50]
    for h in data["hosts"]:
        dev = h["ip"] or "?"
        if h["name"]:
            dev += f"  {h['name']}"
        if h["vendor"]:
            dev += f"  ({h['vendor']})"
        lines.append(f"DEVICE   {dev}")
        if h["os"]:
            lines.append(f"OS       {h['os']}")
            if h.get("os_detail"):
                lines.append(f"         {h['os_detail']}")
            for g in h.get("os_guesses", []):
                lines.append(f"  guess: {g}")
        else:
            lines.append("OS       undetermined "
                         "(needs root + an open & a closed port; try OS Detect)")
        lines.append(f"OPEN PORTS ({len(h['ports'])})")
        if h["ports"]:
            for p in h["ports"]:
                svc = p["service"] or "?"
                prod = f"  {p['product']}" if p["product"] else ""
                lines.append(f"  {p['port'] + '/' + p['proto']:<10} {svc:<14}{prod}")
        else:
            lines.append("  (none open)")
        lines.append(f"VULNERABILITIES ({len(h['vulns'])})")
        if h["vulns"]:
            for vid, vtxt in h["vulns"]:
                lines.append(f"  [{vid}]")
                for vl in vtxt.splitlines()[:8]:
                    if vl.strip():
                        lines.append("    " + vl.strip())
        else:
            lines.append("  (none reported by NSE vuln scripts)")

        # CVE enrichment: pull every CVE id out of the vuln/vulners output,
        # keep the highest CVSS score seen for each, and list them sorted.
        cves = {}
        cve_line = re.compile(r"(CVE-\d{4}-\d{3,7})(?:\s+(\d{1,2}\.\d))?")
        for _, vtxt in h["vulns"]:
            for cm in cve_line.finditer(vtxt):
                cid, score = cm.group(1), cm.group(2)
                prev = cves.get(cid)
                if score and (prev is None or float(score) > float(prev)):
                    cves[cid] = score
                elif cid not in cves:
                    cves[cid] = prev
        if cves:
            ordered = sorted(cves.items(), key=lambda kv: float(kv[1]) if kv[1] else -1, reverse=True)
            lines.append(f"CVES ({len(ordered)})")
            for cid, score in ordered[:20]:
                lines.append(f"  {cid}" + (f"   CVSS {score}" if score else ""))
            if len(ordered) > 20:
                lines.append(f"  … and {len(ordered) - 20} more")
        lines.append("")
    return "\n".join(lines) + "\n"


def stream_scan(args, target):
    """Run an nmap scan: stream live verbose output, then a parsed summary."""
    fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="dokkos_")
    os.close(fd)
    base = ["nmap"] + args + ["--stats-every", "6s", "-oX", xml_path, target]
    # stdbuf forces line-buffered output so the stream updates live instead of
    # arriving in one block when nmap finishes. --stats-every adds a heartbeat.
    cmd = (["stdbuf", "-oL", "-eL"] + base) if shutil.which("stdbuf") else base
    proc = None
    try:
        yield f"$ {' '.join(cmd)}\n\n"
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        timer = threading.Timer(HARD_TIMEOUT_SECONDS, proc.kill)
        timer.start()
        try:
            for line in iter(proc.stdout.readline, ""):
                yield line
            proc.wait()
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
        yield f"\n[exit code {proc.returncode}]\n"
        yield format_summary(xml_path)
    finally:
        # Runs on normal completion AND on client disconnect (GeneratorExit):
        # never leave the scan process or its temp file behind.
        if proc is not None and proc.poll() is None:
            proc.kill()
        try:
            os.remove(xml_path)
        except OSError:
            pass


def stream_proc(cmd):
    """Stream any command's combined output line-by-line (no summary)."""
    line_buffered = (["stdbuf", "-oL", "-eL"] + cmd) if shutil.which("stdbuf") else cmd
    yield f"$ {' '.join(cmd)}\n\n"
    proc = subprocess.Popen(
        line_buffered, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    timer = threading.Timer(HARD_TIMEOUT_SECONDS, proc.kill)
    timer.start()
    try:
        for line in iter(proc.stdout.readline, ""):
            yield line
        proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
    yield f"\n[exit code {proc.returncode}]\n"


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@app.route("/api/config")
def api_config():
    return jsonify(targets=get_scan_targets(), wlan_mon=WIFI_MON or detect_monitor_iface())


@app.route("/api/discover", methods=["POST"])
def api_discover():
    if shutil.which("nmap") is None:
        return jsonify(error="nmap is not installed"), 500
    targets = get_scan_targets()
    scope = (request.get_json(silent=True) or {}).get("scope", "all")
    if scope == "all":
        chosen = targets
    elif scope in targets:
        chosen = [scope]
    else:
        return jsonify(error="scope not in the configured target list"), 400
    try:
        out, _, _ = run_capture(
            ["nmap", "-sn"] + stealth_prefix(request.get_json(silent=True))
            + ["-oX", "-"] + chosen,
            DISCOVERY_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return jsonify(error="discovery timed out"), 504
    hosts = parse_discovery(out)
    return jsonify(hosts=hosts, count=len(hosts), scope=scope, scanned=chosen)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan")
    target = validate_target(data.get("target"))
    if scan_id not in SCAN_PROFILES:
        return Response("[error] unknown scan profile\n", mimetype="text/plain", status=400)
    if target is None:
        return Response("[error] no valid target selected\n", mimetype="text/plain", status=400)
    if shutil.which("nmap") is None:
        return Response("[error] nmap is not installed\n", mimetype="text/plain", status=500)
    cmd_args = stealth_prefix(data) + SCAN_PROFILES[scan_id]["args"]
    return Response(stream_with_context(stream_scan(cmd_args, target)), mimetype="text/plain")


@app.route("/api/settings", methods=["POST"])
def api_settings():
    global WIFI_MON
    data = request.get_json(silent=True) or {}
    if "wlan_mon" in data:
        v = (data.get("wlan_mon") or "").strip()
        if v == "":
            WIFI_MON = None
        elif re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", v):
            WIFI_MON = v
        else:
            return jsonify(error="invalid interface name"), 400
    return jsonify(ok=True, wlan_mon=WIFI_MON)


@app.route("/api/bt_discover", methods=["POST"])
def api_bt_discover():
    if shutil.which("bluetoothctl") is None:
        return jsonify(error="bluetoothctl (BlueZ) is not installed"), 500
    try:
        # timed scan, then dump what was discovered
        subprocess.run(["bluetoothctl", "--timeout", "12", "scan", "on"],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, timeout=25)
        out, _, _ = run_capture(["bluetoothctl", "devices"], 10)
    except subprocess.TimeoutExpired:
        return jsonify(error="bluetooth scan timed out"), 504
    except (OSError, subprocess.SubprocessError) as e:
        return jsonify(error=f"bluetooth scan failed: {e}"), 500
    devices = parse_bt_devices(out)
    # BLE recon enrichment: pull address type, RSSI, service UUIDs and the
    # manufacturer/company id for each device (best-effort, capped, read-only).
    for dev in devices[:15]:
        try:
            info_out, _, _ = run_capture(["bluetoothctl", "info", dev["mac"]], 6)
            info = parse_bt_info(info_out)
            dev["type"] = info["type"]
            dev["rssi"] = info["rssi"]
            dev["services"] = len(info["uuids"])
            dev["uuids"] = info["uuids"][:6]
            dev["manufacturer"] = info["manufacturer"]
        except (OSError, subprocess.SubprocessError):
            pass
    return jsonify(devices=devices, count=len(devices))


@app.route("/api/bt_discover_stream", methods=["POST"])
def api_bt_discover_stream():
    if shutil.which("bluetoothctl") is None:
        return Response("[error] bluetoothctl (BlueZ) is not installed\n",
                        mimetype="text/plain", status=500)

    def gen():
        yield "$ bluetoothctl --timeout 12 scan on\n"
        yield "  controller in discovery, enumerating classic + BLE…\n\n"
        try:
            subprocess.run(["bluetoothctl", "--timeout", "12", "scan", "on"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=25)
            devs_out, _, _ = run_capture(["bluetoothctl", "devices"], 10)
        except subprocess.TimeoutExpired:
            yield "[error] bluetooth scan timed out\n"
            return
        except (OSError, subprocess.SubprocessError) as e:
            yield f"[error] bluetooth scan failed: {e}\n"
            return
        devices = parse_bt_devices(devs_out)
        yield f"discovered {len(devices)} device(s); pulling BLE recon…\n\n"
        for dev in devices[:15]:
            yield f"• {dev.get('name') or dev['mac']}\n"
            try:
                info_out, _, _ = run_capture(["bluetoothctl", "info", dev["mac"]], 6)
                info = parse_bt_info(info_out)
                dev["type"] = info["type"]
                dev["rssi"] = info["rssi"]
                dev["services"] = len(info["uuids"])
                dev["uuids"] = info["uuids"][:6]
                dev["manufacturer"] = info["manufacturer"]
                yield f"    addr   {dev['mac']}{('  ['+info['type']+']') if info['type'] else ''}\n"
                if info["rssi"]:
                    yield f"    rssi   {info['rssi']} dBm\n"
                yield (f"    svcs   {len(info['uuids'])}"
                       f"{('  ('+', '.join(info['uuids'][:4])+')') if info['uuids'] else ''}\n")
                if info["manufacturer"]:
                    yield f"    mfr    {info['manufacturer']}\n"
            except (OSError, subprocess.SubprocessError):
                yield f"    addr   {dev['mac']}  (info unavailable)\n"
            yield "\n"
        yield f"found {len(devices)} bluetooth device(s).\n"
        yield "@@DEVICES@@" + json.dumps(devices) + "\n"

    return Response(stream_with_context(gen()), mimetype="text/plain")


@app.route("/api/bt_scan", methods=["POST"])
def api_bt_scan():
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan")
    mac = validate_mac(data.get("target"))
    if scan_id not in BT_PROFILES:
        return Response("[error] unknown bluetooth profile\n", mimetype="text/plain", status=400)
    if mac is None:
        return Response("[error] invalid bluetooth address (need AA:BB:CC:DD:EE:FF)\n",
                        mimetype="text/plain", status=400)
    prof = BT_PROFILES[scan_id]
    if shutil.which(prof["cmd"][0]) is None:
        return Response(
            f"[error] {prof['cmd'][0]} is not installed — needed for the {prof['label']} "
            f"profile.\n  classic/BLE tools live in the bluez package; "
            f"'bluing' (for Vuln) is a separate install.\n",
            mimetype="text/plain", status=500)
    cmd = prof["cmd"] + [mac]
    return Response(stream_with_context(stream_proc(cmd)), mimetype="text/plain")


@app.route("/api/port_scan", methods=["POST"])
def api_port_scan():
    data = request.get_json(silent=True) or {}
    target = validate_target(data.get("target"))
    port = validate_port(data.get("port"))
    if target is None:
        return Response("[error] no valid target\n", mimetype="text/plain", status=400)
    if port is None:
        return Response("[error] invalid port\n", mimetype="text/plain", status=400)
    if shutil.which("nmap") is None:
        return Response("[error] nmap is not installed\n", mimetype="text/plain", status=500)
    # Service-aware: the browser sends the detected service name; we map it to a
    # fixed NSE script set (no arbitrary scripts can be passed). Unknown -> generic.
    service = (data.get("service") or "").strip().lower()
    scripts = SERVICE_SCRIPTS.get(service, DEFAULT_PORT_SCRIPTS)
    args = stealth_prefix(data) + ["-v", "-sV", "-p", str(port), "--script", scripts, "-T4"]
    return Response(stream_with_context(stream_scan(args, target)), mimetype="text/plain")


@app.route("/api/wifi_scan", methods=["POST"])
def api_wifi_scan():
    if shutil.which("airodump-ng") is None:
        return jsonify(error="airodump-ng (aircrack-ng) is not installed"), 500
    iface = WIFI_MON or detect_monitor_iface()
    if not iface:
        return jsonify(error="no monitor interface — run 'sudo airmon-ng start wlan0' "
                             "then relaunch with --wlan-mon wlan0mon"), 400
    tmpdir = tempfile.mkdtemp(prefix="dokkos_wifi_")
    prefix = os.path.join(tmpdir, "cap")
    try:
        try:
            subprocess.run(
                ["timeout", "14", "airodump-ng", "--output-format", "csv",
                 "--write-interval", "1", "--write", prefix, iface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=25,
            )
        except subprocess.TimeoutExpired:
            pass
        except (OSError, subprocess.SubprocessError) as e:
            return jsonify(error=f"airodump failed: {e}"), 500
        csvs = sorted(glob.glob(prefix + "*.csv"))
        text = ""
        if csvs:
            try:
                with open(csvs[-1], encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                pass
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    parsed = parse_airodump_csv(text)
    return jsonify(iface=iface, count=len(parsed["aps"]), **parsed)


@app.route("/api/launch", methods=["POST"])
def api_launch():
    tool_id = (request.get_json(silent=True) or {}).get("tool")
    if tool_id not in TOOLS:
        return jsonify(error="unknown tool"), 400
    tool = TOOLS[tool_id]
    if shutil.which(tool["cmd"][0]) is None:
        return jsonify(error=f"{tool['label']} is not installed"), 404
    term = find_terminal()
    if term is None:
        return jsonify(error="no terminal emulator found — edit TERMINAL_CANDIDATES"), 500
    if not os.environ.get("DISPLAY"):
        return jsonify(error="no DISPLAY — run the app from a desktop session (sudo -E)"), 500

    # term + the tool, wrapped so the window stays open after the tool exits.
    inner = " ".join(tool["cmd"]) + '; echo; read -n1 -r -p "[finished] press any key to close…"'
    cmd = term + ["bash", "-lc", inner]
    try:
        subprocess.Popen(cmd, env=os.environ.copy())
    except Exception as e:  # noqa: BLE001
        return jsonify(error=f"launch failed: {e}"), 500
    return jsonify(ok=True, launched=tool["label"])


@app.route("/")
def index():
    return PAGE


# ---------------------------------------------------------------------------
# Frontend — interactive HUD, inlined.
# ---------------------------------------------------------------------------
PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<title>DokkOS</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%230b0d13'/%3E%3Cpath d='M9 12 L11 5 L14 12' fill='none' stroke='%23ff4533' stroke-width='2' stroke-linejoin='round'/%3E%3Cpath d='M23 12 L21 5 L18 12' fill='none' stroke='%23ff4533' stroke-width='2' stroke-linejoin='round'/%3E%3Cpath d='M7 12 Q16 10 25 12 L23 21 Q16 27 9 21 Z' fill='none' stroke='%23ff4533' stroke-width='2' stroke-linejoin='round'/%3E%3Cpath d='M11 16 l3 1 -3 1.5 Z' fill='%23ff4533'/%3E%3Cpath d='M21 16 l-3 1 3 1.5 Z' fill='%23ff4533'/%3E%3Cpath d='M13 21 q3 1.5 6 0' fill='none' stroke='%23ff4533' stroke-width='1.4'/%3E%3C/svg%3E">
<style>
  :root{--scr:#0b0d13;--scr2:#11141d;--pnl:#161a25;--ln:#262c3b;
    --em:#ff4533;--emd:#8f261d;--gh:#5ff0d8;--sm:#8a91a3;--bn:#e8eaf0}
  *{box-sizing:border-box}
  html,body{margin:0;height:100%}
  body{background:#05060a;color:var(--bn);font-family:"JetBrains Mono","DejaVu Sans Mono",ui-monospace,monospace;overflow:hidden}
  .scr{position:fixed;inset:0;background:var(--scr);display:grid;grid-template-rows:auto 1fr auto}
  .scr::before{content:"";position:absolute;inset:0;background-image:linear-gradient(45deg,#ffffff08 25%,transparent 25%,transparent 75%,#ffffff08 75%);background-size:24px 24px;opacity:.22;pointer-events:none}

  .top{display:flex;align-items:center;gap:12px;padding:9px 14px;border-bottom:1px solid var(--ln);position:relative;z-index:2}
  .stat{font-size:14px;color:var(--sm);letter-spacing:.1em;white-space:nowrap}
  .stat b{color:var(--em)}
  .stealth{font-family:inherit;font-size:12px;letter-spacing:.14em;color:var(--sm);background:var(--scr2);border:1px solid var(--ln);border-radius:7px;padding:11px 16px;min-height:46px;margin-left:auto;cursor:pointer;white-space:nowrap}
  .uimode{display:flex;border:1px solid var(--ln);border-radius:9px;overflow:hidden}
  .um{font-family:inherit;font-size:14px;font-weight:700;letter-spacing:.22em;color:var(--sm);background:var(--scr2);border:none;padding:11px 22px;min-height:46px;cursor:pointer}
  .um.on{background:#ff45331a;color:var(--em)}
  .stealth.on{color:var(--gh);border-color:var(--gh);background:#5ff0d814}
  .tabs{display:flex;gap:5px;flex:1;justify-content:center;flex-wrap:wrap}
  .spacer{flex:1}
  .tab{font-size:14px;color:var(--sm);padding:11px 16px;min-height:44px;display:flex;align-items:center;border:1px solid transparent;border-radius:6px;cursor:pointer;white-space:nowrap}
  .tab:hover{color:var(--bn)}
  .tab.on{color:var(--bn);background:#ff45331a;border-color:var(--emd)}
  .mark{font-weight:700;letter-spacing:.16em;display:flex;align-items:center;gap:7px}
  .maskico{flex-shrink:0}
  .mark span{color:var(--em)}
  .mark small{font-size:8px;letter-spacing:.34em;color:var(--sm);margin-left:4px;align-self:flex-end;margin-bottom:2px}
  .prog{position:absolute;left:0;bottom:-1px;height:2px;width:0;background:var(--em);transition:width .3s}
  .prog.run{animation:prog 2.4s linear infinite}
  @keyframes prog{0%{width:6%}50%{width:72%}100%{width:96%}}

  main{display:grid;grid-template-columns:284px 1fr 132px;min-height:0;position:relative;z-index:2}
  .col{min-height:0;min-width:0;overflow:auto}
  .col,.out,#hosts{scrollbar-width:thin;scrollbar-color:var(--emd) transparent}
  .col::-webkit-scrollbar,.out::-webkit-scrollbar,#hosts::-webkit-scrollbar{width:8px;height:8px}
  .col::-webkit-scrollbar-track,.out::-webkit-scrollbar-track,#hosts::-webkit-scrollbar-track{background:#0d0f16}
  .col::-webkit-scrollbar-thumb,.out::-webkit-scrollbar-thumb,#hosts::-webkit-scrollbar-thumb{background:linear-gradient(var(--emd),var(--em));border-radius:8px;border:2px solid #0d0f16}
  .col::-webkit-scrollbar-thumb:hover,.out::-webkit-scrollbar-thumb:hover,#hosts::-webkit-scrollbar-thumb:hover{background:var(--em)}
  .list{border-right:1px solid var(--ln);padding:14px 13px;display:flex;flex-direction:column;gap:9px;position:relative;z-index:7}
  .lbl{font-size:12px;letter-spacing:.2em;color:var(--sm);margin:2px 0 4px;display:flex;justify-content:space-between;align-items:center}
  .scanbtn{font-size:14px;letter-spacing:.1em;color:var(--em);border:1px solid var(--emd);background:#ff45331a;border-radius:7px;padding:11px 16px;min-height:44px;cursor:pointer}
  .modes{display:flex;margin:0 0 7px;border:1px solid var(--ln);border-radius:6px;overflow:hidden}
  .mode{flex:1;font-family:inherit;font-size:13px;letter-spacing:.08em;color:var(--sm);background:transparent;border:none;padding:16px 4px;min-height:56px;cursor:pointer}
  .mode.on{background:#ff45331a;color:var(--bn)}
  .scope{width:100%;margin:0 0 4px;background:var(--scr2);color:var(--bn);border:1px solid var(--ln);border-radius:6px;padding:15px 12px;min-height:50px;font-family:inherit;font-size:15px;letter-spacing:.04em;outline:none}
  .scope:focus{border-color:var(--em)}
  .host{display:flex;align-items:center;gap:10px;background:var(--scr2);border:1px solid var(--ln);border-radius:7px;padding:15px 12px;min-height:60px;font-size:14px;color:var(--sm);cursor:pointer;text-align:left}
  .host:hover{border-color:var(--emd)}
  .host.on{background:#ff45331f;border-color:var(--em);color:var(--bn)}
  .host i,.host .ico{font-size:15px;flex-shrink:0;color:var(--gh)}
  .host.on i,.host.on .ico{color:var(--em)}
  .host.act{border-left:3px solid var(--gh)}
  .wifinote{font-size:11px;line-height:1.55;color:var(--sm);background:var(--scr2);border:1px solid var(--ln);border-left:3px solid var(--gh);border-radius:6px;padding:8px 9px;margin:0 0 6px}
  .wifinote b{color:var(--gh);letter-spacing:.1em;text-transform:uppercase;font-size:10px}
  .wifinote code{color:var(--bn);background:#0d0f16;border:1px solid var(--ln);padding:1px 4px;border-radius:3px;font-size:10.5px;word-break:break-all}
  .wifinote .cmd2{margin-top:5px}
  .ports{display:flex;flex-wrap:wrap;gap:7px;align-items:center;padding:9px 14px;border-bottom:1px solid var(--ln);background:#0d0f16}
  .portlbl{font-size:12px;letter-spacing:.12em;color:var(--sm)}
  .port{font-family:inherit;font-size:14px;color:var(--bn);background:var(--scr2);border:1px solid var(--emd);border-radius:6px;padding:12px 15px;min-height:46px;cursor:pointer}
  .port:hover{background:#ff45331f}
  .host .hn{display:block;line-height:1.2}
  .host .hv{display:block;font-size:11px;color:var(--sm)}
  .empty{font-size:13px;color:var(--sm);padding:10px 6px;line-height:1.6}

  .center{display:flex;flex-direction:column;min-height:0;min-width:0;position:relative;z-index:1}
  .tcard{display:flex;align-items:center;gap:13px;padding:14px 16px;border-bottom:1px solid var(--ln);background:#ff45330a}
  .tcard-portrait{width:50px;height:50px;border:1px solid var(--ln);background:#0d0f16;display:flex;align-items:center;justify-content:center;color:#3a4150;flex-shrink:0;position:relative}
  .tcard.active .tcard-portrait{border-color:var(--emd)}
  .tcard-portrait::after{content:"";position:absolute;left:5px;right:5px;bottom:4px;height:3px;background:repeating-linear-gradient(90deg,var(--emd) 0 5px,transparent 5px 9px);opacity:0}
  .tcard.active .tcard-portrait::after{opacity:1}
  .tcard-name{font-size:24px;font-weight:700;letter-spacing:.05em;line-height:1.05}
  .tcard-sub{font-size:13px;color:var(--sm);margin-top:2px}
  .tcard-addr{margin-left:auto;text-align:right}
  .tcard-addr small{display:block;font-size:11px;letter-spacing:.18em;color:var(--em)}
  .tcard-addr span{font-size:17px;color:var(--bn)}
  .tcard-status{display:flex;align-items:center;gap:8px;font-size:13px;letter-spacing:.1em;color:var(--sm);padding-left:13px;border-left:1px solid var(--ln);min-width:118px}
  .tcard-dot{width:8px;height:8px;border-radius:50%;background:var(--sm);flex-shrink:0}
  .tcard.calling .tcard-status{color:var(--em)}
  .tcard.calling .tcard-dot{background:var(--em);animation:tpulse 1s infinite}
  @keyframes tpulse{50%{opacity:.25}}
  pre.out{flex:1;margin:0;overflow:auto;padding:15px 18px;font-size:14px;line-height:1.65;color:#c7ccd8;white-space:pre-wrap;word-break:break-word}
  pre.out .cmd{color:var(--gh)}
  pre.out .hint{color:var(--sm)}
  .cursor{display:inline-block;width:.55ch;height:1.05em;vertical-align:-2px;background:var(--em);animation:blink 1s steps(1) infinite}
  @keyframes blink{50%{opacity:0}}

  .rail{border-left:1px solid var(--ln);display:flex;flex-direction:column;overflow:auto;position:relative;z-index:7}
  .op{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:7px;background:transparent;border:none;border-bottom:1px solid var(--ln);font-family:inherit;color:var(--bn);font-size:12px;letter-spacing:.06em;padding:9px 4px;text-align:center;cursor:pointer}
  .op:hover{color:var(--bn);background:#ffffff08}
  .op.on{background:#ff45331a}
  .op{min-height:66px;line-height:1.15}
  .op i,.op .ico{font-size:25px}
  .rail .op .ico,.rail .op i{color:var(--gh)}
  .rail .op:hover .ico,.rail .op:hover i,.rail .op.on .ico,.rail .op.on i{color:var(--em)}
  .op:disabled{opacity:.35;cursor:not-allowed}

  .bot{display:flex;align-items:center;gap:10px;padding:9px 14px;border-top:1px solid var(--ln);position:relative;z-index:2}
  .tools{display:flex;gap:7px;overflow-x:auto;flex:1;scrollbar-width:none}
  .tools::-webkit-scrollbar{display:none}
  .tool{font-size:13px;letter-spacing:.08em;color:var(--bn);background:var(--scr2);border:1px solid var(--ln);border-radius:6px;padding:13px 16px;min-height:52px;cursor:pointer;display:flex;align-items:center;gap:8px}
  .tool:hover{border-color:var(--em)}
  .tool i,.tool .ico{color:var(--em);font-size:16px}
  .callbtn{margin-left:auto;display:flex;align-items:center;gap:9px;background:#ff45331f;border:1px solid var(--em);color:var(--bn);padding:10px 26px;border-radius:30px;font-size:15px;letter-spacing:.14em;cursor:pointer}
  .callbtn:hover{background:#ff45332e}
  .callbtn.run{animation:pulse 1.2s infinite}
  .callbtn i,.callbtn .ico{color:var(--em);font-size:18px}
  .callbtn:disabled{opacity:.4;cursor:not-allowed;animation:none}
  @keyframes pulse{50%{background:#ff45330d;border-color:var(--emd)}}

  .toast{position:fixed;left:50%;bottom:70px;transform:translateX(-50%);background:var(--pnl);border:1px solid var(--emd);color:var(--bn);font-size:14px;letter-spacing:.05em;padding:9px 16px;border-radius:8px;z-index:20;opacity:0;transition:opacity .2s;pointer-events:none}
  .toast.show{opacity:1}

  .gear{display:flex;align-items:center;justify-content:center;width:46px;height:46px;flex-shrink:0;
    background:var(--scr2);border:1px solid var(--ln);border-radius:8px;color:var(--sm);cursor:pointer}
  .gear:hover{border-color:var(--em);color:var(--em)}
  .gear .ico{width:20px;height:20px}
  .modal{position:fixed;inset:0;z-index:30;display:none;align-items:center;justify-content:center;background:#000a;backdrop-filter:blur(2px)}
  .modal.show{display:flex}
  .sheet{width:min(440px,92vw);background:var(--pnl);border:1px solid var(--emd);border-radius:14px;padding:20px 22px;box-shadow:0 0 60px #ff45332e}
  .sheet-head{display:flex;justify-content:space-between;align-items:center;font-size:14px;font-weight:700;letter-spacing:.3em;color:var(--em);margin-bottom:16px}
  .sheet .x{background:none;border:none;color:var(--sm);font-size:18px;cursor:pointer}
  .srow{display:flex;align-items:center;justify-content:space-between;gap:14px;margin:11px 0;font-size:14px;color:var(--bn)}
  .srow select,.srow input{font-family:inherit;font-size:14px;background:var(--scr2);color:var(--bn);border:1px solid var(--ln);border-radius:7px;padding:11px 12px;min-height:46px;min-width:170px;outline:none}
  .srow select:focus,.srow input:focus{border-color:var(--em)}
  .srow-note{font-size:11px;line-height:1.5;color:var(--sm);margin:12px 0 4px}
  .save{width:100%;margin-top:8px;font-family:inherit;font-size:15px;font-weight:700;letter-spacing:.24em;
    background:#ff45331f;border:1px solid var(--em);color:var(--bn);border-radius:9px;padding:14px;min-height:50px;cursor:pointer}
  .save:hover{background:#ff45332e}

  /* R6-style call takeover */
  .callscreen{position:absolute;inset:0;display:none;flex-direction:column;align-items:center;justify-content:center;z-index:6;overflow:hidden;pointer-events:none;
    background:radial-gradient(circle at 50% 40%, #20100f 0%, var(--scr) 70%)}
  .callscreen.show{display:flex}
  .cs-frame{pointer-events:none}
  .cs-grid{position:absolute;inset:0;pointer-events:none;opacity:.5;
    background-image:linear-gradient(#ff45331a 1px,transparent 1px),linear-gradient(90deg,#ff45331a 1px,transparent 1px);
    background-size:34px 34px;mask:radial-gradient(circle at 50% 42%,#000 0%,transparent 72%);-webkit-mask:radial-gradient(circle at 50% 42%,#000 0%,transparent 72%)}
  .cs-scanline{position:absolute;left:0;right:0;height:120px;pointer-events:none;opacity:0;
    background:linear-gradient(#ff45330a,#ff453326,#ff45330a)}
  .callscreen[data-state="scanning"] .cs-scanline{opacity:1;animation:csscan 2.6s linear infinite}
  @keyframes csscan{0%{transform:translateY(-130px)}100%{transform:translateY(105vh)}}
  .cs-frame{position:relative;display:flex;flex-direction:column;align-items:center;gap:13px;padding:44px 64px}
  .cs-bracket{position:absolute;width:30px;height:30px;border:2px solid var(--em)}
  .cs-bracket.tl{top:0;left:0;border-right:none;border-bottom:none}
  .cs-bracket.tr{top:0;right:0;border-left:none;border-bottom:none}
  .cs-bracket.bl{bottom:0;left:0;border-right:none;border-top:none}
  .cs-bracket.br{bottom:0;right:0;border-left:none;border-top:none}
  .callscreen[data-state="scanning"] .cs-bracket{animation:csbrk 1.1s ease-in-out infinite}
  @keyframes csbrk{50%{box-shadow:0 0 12px var(--em)}}
  .cs-eyebrow{font-size:11px;letter-spacing:.46em;color:var(--em);text-transform:uppercase}
  .cs-name{font-size:32px;font-weight:700;letter-spacing:.05em;color:var(--bn);text-align:center;line-height:1.05;max-width:460px;overflow-wrap:anywhere;text-shadow:0 0 18px #ff45334d}
  .cs-addr{font-size:14px;letter-spacing:.24em;color:var(--sm);margin-top:-5px}
  .cs-call{position:relative;width:148px;height:148px;border-radius:50%;margin:16px 0 6px;cursor:pointer;pointer-events:auto;
    display:flex;align-items:center;justify-content:center;color:var(--em);overflow:hidden;
    background:radial-gradient(circle,#ff45332e 0%,#ff45330d 70%);border:2px solid var(--em);
    box-shadow:0 0 34px #ff45334d, inset 0 0 26px #ff45331f}
  .cs-call:hover{box-shadow:0 0 52px #ff453388, inset 0 0 30px #ff45332e}
  .cs-call:active{transform:scale(.95)}
  .cs-ico{position:relative;z-index:2;display:flex}
  .cs-ico .ico{width:52px;height:52px}
  .cs-sweep{position:absolute;inset:0;border-radius:50%;opacity:0;
    background:conic-gradient(from 0deg, transparent 0deg, #ff45334d 38deg, transparent 70deg)}
  .callscreen[data-state="scanning"] .cs-sweep,.callscreen[data-state="sweeping"] .cs-sweep{opacity:1;animation:cspin 1.5s linear infinite}
  @keyframes cspin{100%{transform:rotate(360deg)}}
  .cs-ring{position:absolute;inset:-2px;border-radius:50%;border:2px solid var(--em);opacity:0;animation:csring 2.4s ease-out infinite;pointer-events:none}
  .cs-ring.r2{animation-delay:.8s}.cs-ring.r3{animation-delay:1.6s}
  @keyframes csring{0%{transform:scale(1);opacity:.6}100%{transform:scale(1.9);opacity:0}}
  .callscreen[data-state="scanning"] .cs-ring,.callscreen[data-state="sweeping"] .cs-ring{animation-duration:1.3s}
  .callscreen[data-state="scanning"] .cs-call,.callscreen[data-state="sweeping"] .cs-call{animation:csbeat 1s ease-in-out infinite}
  @keyframes csbeat{50%{box-shadow:0 0 62px #ff4533c0, inset 0 0 32px #ff45333a}}
  .cs-label{font-size:23px;font-weight:700;letter-spacing:.42em;color:var(--em);padding-left:.42em}
  .callscreen[data-state="scanning"] .cs-label,.callscreen[data-state="sweeping"] .cs-label{animation:csblink 1.1s steps(1) infinite}
  @keyframes csblink{50%{opacity:.5}}
  .cs-status{font-size:13px;letter-spacing:.22em;color:var(--em);text-transform:uppercase;min-height:17px}
  .cs-hint{font-size:12px;letter-spacing:.16em;color:var(--sm)}
  .cs-done{display:none;grid-template-columns:repeat(2,minmax(150px,200px));gap:10px;margin:4px 0 2px;max-width:440px}
  .callscreen[data-state="done"] .cs-done{display:grid}
  .callscreen[data-state="done"] .cs-status{display:none}
  .cs-tile{background:#0d1f1c;border:1px solid #5ff0d83a;border-left:3px solid var(--gh);border-radius:8px;padding:10px 12px;text-align:left;min-height:62px}
  .cs-tk{font-size:10px;letter-spacing:.26em;color:var(--gh);text-transform:uppercase}
  .cs-tv{font-size:18px;font-weight:700;color:var(--bn);line-height:1.1;margin-top:3px;overflow-wrap:anywhere}
  .cs-td{font-size:11px;letter-spacing:.06em;color:var(--sm);margin-top:3px;overflow-wrap:anywhere}
  .cs-tile.wide{grid-column:1 / -1}
  /* done: turns teal, rings stop */
  .callscreen[data-state="done"] .cs-call{color:var(--gh);border-color:var(--gh);
    background:radial-gradient(circle,#5ff0d82e 0%,#5ff0d80d 70%);box-shadow:0 0 36px #5ff0d84d, inset 0 0 26px #5ff0d81f}
  .callscreen[data-state="done"] .cs-ring,.callscreen[data-state="done"] .cs-sweep{display:none}
  .callscreen[data-state="done"] .cs-label,.callscreen[data-state="done"] .cs-status,
  .callscreen[data-state="done"] .cs-eyebrow,.callscreen[data-state="done"] .cs-name{color:var(--gh)}
  .callscreen[data-state="done"] .cs-name{text-shadow:0 0 18px #5ff0d84d}
</style>
</head>
<body>
<div class="scr">
  <div class="top">
    <div class="stat">Hosts <b id="hostcount">0</b></div>
    <div class="uimode" id="uimode">
      <button class="um" data-um="pro">PRO</button>
      <button class="um on" data-um="r6">R6</button>
    </div>
    <div class="spacer"></div>
    <div class="mark"><svg class="maskico" width="22" height="22" viewBox="0 0 32 32" aria-hidden="true"><path d="M9 12 L11 5 L14 12" fill="none" stroke="var(--em)" stroke-width="2" stroke-linejoin="round"/><path d="M23 12 L21 5 L18 12" fill="none" stroke="var(--em)" stroke-width="2" stroke-linejoin="round"/><path d="M7 12 Q16 10 25 12 L23 21 Q16 27 9 21 Z" fill="none" stroke="var(--em)" stroke-width="2" stroke-linejoin="round"/><path d="M11 16 l3 1 -3 1.5 Z" fill="var(--em)"/><path d="M21 16 l-3 1 3 1.5 Z" fill="var(--em)"/><path d="M13 21 q3 1.5 6 0" fill="none" stroke="var(--em)" stroke-width="1.4"/></svg> Dokk<span>OS</span><small>recon v2.6</small></div>
    <div class="prog" id="prog"></div>
  </div>

  <main>
    <section class="col list">
      <div class="modes">
        <button class="mode on" data-mode="net">Network</button>
        <button class="mode" data-mode="bt">Bluetooth</button>
        <button class="mode" data-mode="wifi">Wi-Fi</button>
      </div>
      <div class="lbl"><span id="listlabel">Hosts</span> <button class="scanbtn" id="discover">Scan</button></div>
      <select id="scope" class="scope" aria-label="network scope"></select>
      <div id="wifinote" class="wifinote" style="display:none"></div>
      <div id="hosts"><div class="empty">Pick a scope, then tap Scan to sweep the network for live hosts.</div></div>
    </section>

    <section class="center">
      <div class="tcard" id="tcard">
        <div class="tcard-portrait">
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M3 9h18M8 21h8M12 17v4"/></svg>
        </div>
        <div>
          <div class="tcard-name" id="tname">NO TARGET</div>
          <div class="tcard-sub" id="tsub">select a host from the list</div>
        </div>
        <div class="tcard-addr"><small id="taddrlabel">ADDRESS</small><span id="taddr">—</span></div>
        <div class="tcard-status"><span class="tcard-dot"></span><span id="tphase">standby</span></div>
      </div>
      <div class="ports" id="ports" style="display:none"></div>
      <pre class="out" id="out"><span class="hint">// 1. sweep the subnet  // 2. tap a host  // 3. run a scan or CALL
// only scan systems you own or are authorised to test.</span>
</pre>
      <div class="callscreen" id="callscreen">
        <div class="cs-grid"></div>
        <div class="cs-scanline"></div>
        <div class="cs-frame">
          <span class="cs-bracket tl"></span><span class="cs-bracket tr"></span>
          <span class="cs-bracket bl"></span><span class="cs-bracket br"></span>
          <div class="cs-eyebrow" id="cseyebrow">incoming target</div>
          <div class="cs-name" id="csname">TARGET</div>
          <div class="cs-addr" id="csaddr">—</div>
          <button class="cs-call" id="bigcall" aria-label="call target">
            <span class="cs-sweep"></span>
            <span class="cs-ring"></span><span class="cs-ring r2"></span><span class="cs-ring r3"></span>
            <span class="cs-ico" id="csico"></span>
          </button>
          <div class="cs-label" id="cslabel">CALL</div>
          <div class="cs-status" id="csstatus"></div>
          <div class="cs-done" id="csdone"></div>
          <div class="cs-hint" id="cshint">tap to establish contact // run recon</div>
        </div>
      </div>
    </section>

    <section class="col rail" id="rail"></section>
  </main>

  <div class="bot">
    <div class="tools" id="tools"></div>
    <button class="stealth on" id="stealth" title="randomise our MAC on scans (nmap --spoof-mac 0)">STEALTH ON</button>
    <button class="gear" id="gear" aria-label="settings"></button>
  </div>
</div>

<div class="modal" id="settings">
  <div class="sheet">
    <div class="sheet-head"><span>SETTINGS</span><button class="x" id="setclose" aria-label="close">✕</button></div>
    <label class="srow"><span>Default mode</span>
      <select id="set-ui"><option value="r6">R6 (graphics)</option><option value="pro">PRO (terminal)</option></select></label>
    <label class="srow"><span>Default scan</span>
      <select id="set-prof"></select></label>
    <label class="srow"><span>Stealth (random MAC)</span>
      <select id="set-stealth"><option value="on">on</option><option value="off">off</option></select></label>
    <label class="srow"><span>Monitor interface</span>
      <input id="set-wlan" placeholder="wlan0mon" autocomplete="off"></label>
    <div class="srow-note">Mode / scan / stealth are saved on this device. Monitor interface is applied to the running server.</div>
    <button class="save" id="setsave">SAVE</button>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const ICONS={
  phone:'<path d="M5 4h4l2 5-2.5 1.5a11 11 0 0 0 5 5L15 13l5 2v4a1 1 0 0 1-1 1A16 16 0 0 1 3 5a1 1 0 0 1 1-1z"/>',
  stop:'<rect x="6" y="6" width="12" height="12" rx="1.5"/>',
  radar:'<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="1.5"/><path d="M12 12l7-4"/>',
  wifi:'<path d="M4 9a14 14 0 0 1 16 0"/><path d="M7.5 12.5a9 9 0 0 1 9 0"/><path d="M10.5 16a4 4 0 0 1 3 0"/><circle cx="12" cy="19" r=".5"/>',
  antenna:'<path d="M12 9v11"/><circle cx="12" cy="6" r="2"/><path d="M7 8a6 6 0 0 1 10 0"/>',
  network:'<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M11 7l-5 9.5"/><path d="M13 7l5 9.5"/>',
  caret:'<path d="M9 6l6 6-6 6"/>',
  square:'<rect x="5" y="5" width="14" height="14" rx="1.5"/>',
  bt:'<path d="M6.5 8.5L17.5 15.5L12 20L12 4L17.5 8.5L6.5 15.5"/>',
  search:'<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
  shield:'<path d="M12 3l7 3v5c0 4-3 7-7 9-4-2-7-5-7-9V6z"/>',
  chip:'<rect x="6" y="6" width="12" height="12" rx="1"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>',
  layers:'<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>',
  terminal:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/>',
  gear:'<circle cx="12" cy="12" r="3.2"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9L17 7M7 17l-2.1 2.1"/>'
};
const I=(n,s=22)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n]||''}</svg>`;

const NET_SCANS = [
  {id:"quick",    en:"Quick"},
  {id:"services", en:"Services"},
  {id:"full",     en:"All Ports"},
  {id:"os",       en:"OS Detect"},
  {id:"vuln",     en:"Vulns"},
  {id:"deep",     en:"Full Recon"},
];
const BT_SCANS = [
  {id:"info",     en:"Info"},
  {id:"services", en:"Services"},
  {id:"ping",     en:"L2 Ping"},
  {id:"vuln",     en:"Vuln"},
];
const TOOLS = [
  {id:"metasploit",en:"metasploit",icon:"terminal"},
  {id:"airgeddon", en:"airgeddon", icon:"wifi"},
  {id:"wifite",    en:"wifite",    icon:"antenna"},
  {id:"bettercap", en:"bettercap", icon:"network"},
  {id:"bluing",    en:"bluing",    icon:"bt"},
  {id:"sqlmap",    en:"sqlmap",    icon:"chip"},
  {id:"nikto",     en:"nikto",     icon:"search"},
  {id:"hydra",     en:"hydra",     icon:"shield"},
];

const $ = s => document.querySelector(s);
const out=$("#out"), prog=$("#prog"), toast=$("#toast"),
      callscreen=$("#callscreen"), bigcall=$("#bigcall"),
      tcard=$("#tcard"), tname=$("#tname"), tsub=$("#tsub"), taddr=$("#taddr"), tphase=$("#tphase");
let hosts=[], selected=null, mode="net", profile="deep", running=false, ctrl=null, scopes=[];
let lastWifi={aps:[],clients:[]}, scanHost=null, stealth=true, gen=0, wlanMon=null, called=false;
let uiMode="r6", scanPhase=null, scanPct=0, defProfile="deep";

const scanSet     = () => mode==="net" ? NET_SCANS : (mode==="bt" ? BT_SCANS : []);
const defaultProf = () => mode==="net" ? defProfile : "info";
const deepProf    = () => mode==="net" ? "deep" : "vuln";

$("#tools").innerHTML = TOOLS.map(t=>`<button class="tool" data-tool="${t.id}">${I(t.icon,14)}${t.en}</button>`).join("");

function scanCounts(){
  const t=out.textContent;
  const g=re=>(t.match(re)||[])[1];
  return {ports:g(/OPEN PORTS \((\d+)\)/), vulns:g(/VULNERABILITIES \((\d+)\)/), cves:g(/CVES \((\d+)\)/)};
}
function esc(x){ return String(x==null?"":x).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }
function parseSummary(){
  const t=out.textContent, one=re=>{const m=t.match(re);return m?m[1].trim():null;};
  const dev=t.match(/^DEVICE\s+(\S+)(?:\s+(.+))?/m);
  let vendor=null; if(dev&&dev[2]){ const vm=dev[2].match(/\(([^)]+)\)/); if(vm) vendor=vm[1]; }
  let os=one(/^OS\s+(.+)/m); if(os&&/undetermined/i.test(os)) os=null;
  const osd=one(/^OS\s+.+\n\s+(type .+)/m);
  const ports=[]; const pre=/^\s*(\d+)\/(tcp|udp)\s+(\S+)/gm; let pm;
  while((pm=pre.exec(t))) ports.push(pm[1]+"/"+pm[3]);
  return {device:dev?dev[1]:null, vendor, os, osd, ports,
          portCount:one(/OPEN PORTS \((\d+)\)/)||String(ports.length),
          vulns:one(/VULNERABILITIES \((\d+)\)/)||"0",
          cves:one(/CVES \((\d+)\)/), topcve:one(/CVES \(\d+\)\n\s+(CVE-\d{4}-\d+)/)};
}
function tile(k,v,d,wide){ return `<div class="cs-tile${wide?' wide':''}"><div class="cs-tk">${esc(k)}</div>`+
  `<div class="cs-tv">${esc(v)}</div>${d?`<div class="cs-td">${esc(d)}</div>`:""}</div>`; }
function doneTiles(){
  const s=parseSummary(), out=[];
  if(s.os) out.push(tile("os", s.os, s.osd, true));
  out.push(tile("open ports", s.portCount, s.ports.length?(s.ports.slice(0,4).join(", ")+(s.ports.length>4?" …":"")):""));
  out.push(tile("vulns", s.vulns));
  if(s.cves) out.push(tile("cves", s.cves, s.topcve));
  if(s.vendor) out.push(tile("vendor", s.vendor));
  return out.join("");
}
function setProg(p){ scanPct=p; prog.classList.remove("run"); prog.style.width=Math.max(2,Math.min(99,p))+"%"; }
function parseProgress(t){
  let ph=null;
  if(/OS detection|Initiating OS/i.test(t)) ph="identifying os";
  else if(/NSE:|Script scan|script scanning|Scanning .* scripts/i.test(t)) ph="running scripts · cve check";
  else if(/Service scan|Initiating Service/i.test(t)) ph="fingerprinting services";
  else if(/SYN Stealth|Connect Scan|Initiating .*Scan/i.test(t)) ph="probing ports";
  else if(/Ping Scan|ARP Ping|host discovery|Initiating Ping/i.test(t)) ph="locating host";
  else if(/RSSI|UUID|bluetoothctl|ManufacturerData/i.test(t)) ph="enumerating device";
  if(ph) scanPhase=ph;
  const m=t.match(/([\d.]+)%\s*done/g);
  if(m){ const v=parseFloat(m[m.length-1]); if(!isNaN(v)) setProg(v); }
  if(running) updateCallScreen();
}
function csIco(n){ const e=$("#csico"); if(e) e.innerHTML=I(n,52); }
function updateCallScreen(){
  // Wi-Fi with an AP selected -> its details view, not the call screen.
  if(mode==="wifi" && selected!==null){ callscreen.classList.remove("show"); return; }
  const sel = selected!==null;
  const state = !sel ? (running ? "sweeping" : "sweep")
                     : (running ? "scanning" : (called ? "done" : "idle"));
  // Pro mode only shows the static action prompts; R6 keeps the graphic up throughout.
  const show = (uiMode==="r6") ? true : (state==="idle" || state==="sweep");
  callscreen.classList.toggle("show", show);
  if(!show) return;
  callscreen.dataset.state = state;
  if(sel){
    $("#csname").textContent = (hosts[selected].label||"").toUpperCase() || hosts[selected].addr;
    $("#csaddr").textContent = hosts[selected].addr;
  } else {
    $("#csname").textContent = mode==="net" ? "NETWORK" : (mode==="bt" ? "BLUETOOTH" : "WI-FI");
    $("#csaddr").textContent = mode==="net" ? (scopes.join("  ")||"no scope") : "in range";
  }
  if(state==="sweep"){
    csIco('radar');
    $("#cseyebrow").textContent="ready";
    $("#cslabel").textContent = mode==="net" ? "SWEEP" : "SCAN";
    $("#csstatus").textContent="";
    $("#cshint").textContent="tap to sweep for "+(mode==="net"?"live hosts":mode==="bt"?"devices":"access points");
  } else if(state==="sweeping"){
    csIco('radar');
    $("#cseyebrow").textContent="sweeping";
    $("#cslabel").textContent = mode==="net" ? "SWEEPING" : "SCANNING";
    $("#csstatus").textContent = mode==="net" ? "locating live hosts" : "listening";
    $("#cshint").textContent="tap to abort";
  } else if(state==="scanning"){
    csIco(mode==="bt"?'bt':'radar');
    $("#cseyebrow").textContent="link active";
    $("#cslabel").textContent="CALLING";
    $("#csstatus").textContent=(scanPhase||"establishing link")+(scanPct?("  ·  "+Math.round(scanPct)+"%"):"");
    $("#cshint").textContent="tap to abort";
  } else if(state==="done"){
    csIco('phone');
    $("#cseyebrow").textContent="link complete";
    $("#cslabel").textContent="COMPLETE";
    $("#csdone").innerHTML=doneTiles();
    $("#cshint").textContent="tap to re-scan  //  switch to PRO for full output";
  } else {
    csIco('phone');
    $("#cseyebrow").textContent = mode==="bt" ? "incoming device" : "incoming target";
    $("#cslabel").textContent="CALL";
    $("#csstatus").textContent="";
    $("#cshint").textContent="tap to establish contact // run recon";
  }
}
function setUiMode(m){
  uiMode=m;
  document.querySelectorAll("[data-um]").forEach(b=>b.classList.toggle("on",b.dataset.um===m));
  updateCallScreen();
}

/* ---- settings + on-device prefs ---- */
const PK="dokkos:";
function getPref(k,d){ try{ const v=localStorage.getItem(PK+k); return v===null?d:v; }catch(e){ return d; } }
function setPref(k,v){ try{ localStorage.setItem(PK+k,v); }catch(e){} }
function reflectStealth(){ const b=$("#stealth"); b.classList.toggle("on",stealth); b.textContent=stealth?"STEALTH ON":"STEALTH OFF"; }
function loadPrefs(){
  uiMode   = getPref("ui","r6");
  stealth  = getPref("stealth","on")==="on";
  defProfile = getPref("prof","deep");
  profile  = mode==="net" ? defProfile : defaultProf();
  document.querySelectorAll("[data-um]").forEach(b=>b.classList.toggle("on",b.dataset.um===uiMode));
  reflectStealth();
}
function openSettings(){
  $("#set-ui").value     = uiMode;
  $("#set-prof").value   = defProfile;
  $("#set-stealth").value= stealth ? "on" : "off";
  $("#set-wlan").value   = wlanMon || "";
  $("#settings").classList.add("show");
}
function closeSettings(){ $("#settings").classList.remove("show"); }
async function saveSettings(){
  uiMode     = $("#set-ui").value;       setPref("ui",uiMode);
  defProfile = $("#set-prof").value;      setPref("prof",defProfile);
  stealth    = $("#set-stealth").value==="on"; setPref("stealth",stealth?"on":"off");
  reflectStealth();
  if(mode==="net"){ profile=defProfile; }
  setUiMode(uiMode); renderRail();
  const w=$("#set-wlan").value.trim();
  try{
    const r=await fetch("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({wlan_mon:w})});
    const d=await r.json(); if(d.ok){ wlanMon=d.wlan_mon||null; renderWifiNote(); }
    else if(d.error){ showToast(d.error); return; }
  }catch(e){}
  closeSettings(); showToast("settings saved");
}

const SCAN_ICONS={quick:'radar',services:'network',full:'layers',os:'chip',vuln:'shield',deep:'radar',
                  info:'search',ping:'antenna'};
function renderTabs(){ renderRail(); }   // scan menu now lives in the rail
function renderRail(){
  if(mode==="wifi"){
    $("#rail").innerHTML =
      `<button class="op" id="rescan">${I('radar')}Rescan</button>`+
      `<button class="op" id="details">${I('search')}Details</button>`+
      `<button class="op" id="abort">${I('stop')}Abort</button>`;
    return;
  }
  const locked = selected===null || running;
  const btns = scanSet().map(s=>
    `<button class="op${s.id===profile?' on':''}" data-scan="${s.id}"${locked?' disabled':''}>`+
    `${I(SCAN_ICONS[s.id]||'radar')}${s.en}</button>`).join("");
  $("#rail").innerHTML = btns + `<button class="op" id="abort">${I('stop')}Abort</button>`;
}
function clearPorts(){ const b=$("#ports"); b.innerHTML=""; b.style.display="none"; }
function renderWifiNote(){
  const n=$("#wifinote");
  if(mode!=="wifi"){ n.style.display="none"; return; }
  const ifc=wlanMon||"wlan0mon";
  n.style.display="";
  n.innerHTML =
    `<b>monitor mode</b> · <code>${ifc}</code>`+
    `<div class="cmd2">enable: <code>sudo airmon-ng start wlan0</code></div>`+
    `<div class="cmd2">back to managed: <code>sudo airmon-ng stop ${ifc}</code> &amp;&amp; <code>sudo systemctl restart NetworkManager</code></div>`;
}
function setMode(m){
  if(m===mode) return;
  gen++;                                  // invalidate any in-flight discovery
  if(running){ try{ if(ctrl) ctrl.abort(); }catch(e){} setRunning(false); }
  mode=m; profile=defaultProf(); hosts=[]; selected=null; called=false; clearPorts();
  document.querySelectorAll("[data-mode]").forEach(b=>b.classList.toggle("on",b.dataset.mode===m));
  $("#listlabel").textContent = m==='net' ? "Hosts" : (m==='bt' ? "Devices" : "Access Points");
  $("#discover").textContent  = m==='net' ? "Scan" : (m==='bt' ? "BT Scan" : "Wi-Fi Scan");
  $("#scope").style.display   = m==='net' ? "" : "none";
  renderWifiNote();
  renderTabs(); renderRail(); renderHosts(); renderCard(); updateCallScreen();
}

function setPhase(t,on){ tphase.textContent=t; tcard.classList.toggle("calling",!!on); }
function renderCard(){
  const has = selected!==null, h = has?hosts[selected]:null;
  tname.textContent = has ? (h.label||"").toUpperCase() : "NO TARGET";
  tsub.textContent  = has ? h.sub : "select a target from the list";
  taddr.textContent = has ? h.addr : "—";
  $("#taddrlabel").textContent = has ? (h.wifi?"BSSID":(h.bt?"BT ADDR":"ADDRESS")) : "ADDRESS";
  tcard.classList.toggle("active", has);
}
function setRunning(v){
  running=v;
  if(v){ scanPhase=null; scanPct=0; prog.style.width=""; prog.classList.add("run"); }
  else { prog.classList.remove("run"); prog.style.width="100%"; setTimeout(()=>{ if(!running) prog.style.width="0"; },650); }
  setPhase(v ? "calling…" : (selected!==null ? "ready" : "standby"), v);
  renderRail(); updateCallScreen();
}
function showToast(msg){ toast.textContent=msg; toast.classList.add("show"); setTimeout(()=>toast.classList.remove("show"),2600); }
function write(t,cls){ const n=document.createElement("span"); if(cls)n.className=cls; n.textContent=t; out.appendChild(n); out.scrollTop=out.scrollHeight; }
function cursor(on){ const o=out.querySelector(".cursor"); if(o)o.remove(); if(on){const c=document.createElement("span");c.className="cursor";out.appendChild(c);} }

function renderHosts(){
  $("#hostcount").textContent = hosts.length;
  const box=$("#hosts");
  const empty = mode==='net' ? 'No live hosts yet — pick a scope and tap Scan.'
              : mode==='bt'  ? 'No devices yet — tap BT Scan (needs a Bluetooth adapter, powered on).'
              :                'No APs yet — tap Wi-Fi Scan (needs a monitor-mode interface).';
  if(!hosts.length){ box.innerHTML=`<div class="empty">${empty}</div>`; return; }
  box.innerHTML = hosts.map((h,i)=>{
    const ico = selected===i ? 'caret' : (h.wifi ? 'wifi' : (h.bt ? 'bt' : 'square'));
    return `<button class="host${selected===i?' on':''}${h.active?' act':''}" data-i="${i}">
      ${I(ico,14)}
      <span><span class="hn">${esc(h.label)}</span><span class="hv">${esc(h.sub)}</span></span></button>`;
  }).join("");
}
function selectHost(i){
  selected=i; called=false;
  renderCard(); renderRail();
  setPhase(running?"calling…":"ready", running);
  renderHosts();
  if(mode==="wifi" && !running){ called=true; showAPDetails(); }
  updateCallScreen();
}

async function loadConfig(){
  const sel=$("#scope");
  try{
    const d=await (await fetch("/api/config")).json();
    scopes=d.targets||[]; wlanMon=d.wlan_mon||null; renderWifiNote();
  }catch(e){ scopes=[]; }
  if(!scopes.length){ sel.innerHTML=`<option value="all">no networks configured</option>`; return; }
  sel.innerHTML = `<option value="all">All networks (${scopes.length})</option>`+
    scopes.map(s=>`<option value="${s}">${s}</option>`).join("");
  updateCallScreen();
}

async function discover(){
  if(running) return;
  if(mode==="bt") return discoverBT();
  if(mode==="wifi") return discoverWifi();
  const g=gen, scope=$("#scope").value||"all";
  const shown = scope==="all" ? (scopes.join(" ")||"(none)") : scope;
  selected=null; called=false;
  setRunning(true); setPhase("discovering…", true);
  out.textContent=""; clearPorts(); write("$ nmap -sn "+(stealth?"--spoof-mac 0 ":"")+shown+"\n\n","cmd"); cursor(true);
  ctrl=new AbortController();
  try{
    const r=await fetch("/api/discover",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({scope,stealth}),signal:ctrl.signal});
    const d=await r.json(); if(g!==gen) return; cursor(false);
    if(d.error){ write("[error] "+d.error+"\n"); }
    else{ hosts=(d.hosts||[]).map(h=>({addr:h.ip,label:h.name||h.ip.split(".").slice(-1)[0],sub:h.vendor||h.mac||h.ip,bt:false})); selected=null; renderHosts();
      write(`found ${d.count} live host${d.count===1?"":"s"} across ${(d.scanned||[]).length} network${(d.scanned||[]).length===1?"":"s"}.\n`); updateCallScreen(); }
  }catch(e){ if(e.name!=="AbortError"){ cursor(false); write("[error] "+e.message+"\n"); } }
  finally{ if(g===gen) setRunning(false); }
}

async function discoverBT(){
  const g=gen;
  selected=null; called=false;
  setRunning(true); setPhase("scanning bt…", true);
  out.textContent=""; cursor(true);
  ctrl=new AbortController();
  let raw="", cut=false, first=true;
  try{
    const r=await fetch("/api/bt_discover_stream",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}",signal:ctrl.signal});
    const rd=r.body.getReader(), dec=new TextDecoder();
    while(true){ const {done,value}=await rd.read(); if(done)break;
      if(g!==gen) return;
      const chunk=dec.decode(value,{stream:true}); raw+=chunk;
      if(!cut){
        const i=raw.indexOf("@@DEVICES@@");
        if(i>=0){ const vis=chunk.slice(0,chunk.indexOf("@@DEVICES@@")); if(vis){cursor(false);write(vis,first?"cmd":null);first=false;} cut=true; }
        else { cursor(false); write(chunk, first?"cmd":null); first=false; cursor(true); }
      }
    }
    cursor(false);
    let devs=[]; const i=raw.indexOf("@@DEVICES@@");
    if(i>=0){ try{ devs=JSON.parse(raw.slice(i+11)); }catch(e){} }
    hosts=devs.map(x=>{
      const bits=[];
      if(x.type) bits.push(x.type);
      if(x.rssi) bits.push("RSSI "+x.rssi);
      if(typeof x.services==="number") bits.push(x.services+" svc");
      if(x.manufacturer) bits.push("mfr "+x.manufacturer);
      return {addr:x.mac, label:x.name||x.mac, bt:true, info:x, sub:bits.length?bits.join(" · "):x.mac};
    });
    renderHosts(); updateCallScreen();
  }catch(e){ if(e.name!=="AbortError"){ cursor(false); write("[error] "+e.message+"\n"); } }
  finally{ if(g===gen) setRunning(false); }
}

async function discoverWifi(){
  const g=gen;
  selected=null; called=false;
  setRunning(true); setPhase("scanning wifi…", true);
  out.textContent=""; clearPorts(); write("$ airodump-ng  (14s capture)\n\n","cmd"); cursor(true);
  ctrl=new AbortController();
  try{
    const r=await fetch("/api/wifi_scan",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}",signal:ctrl.signal});
    const d=await r.json(); if(g!==gen) return; cursor(false);
    if(d.error){ write("[error] "+d.error+"\n"); }
    else{
      lastWifi={aps:d.aps||[], clients:d.clients||[]};
      hosts=lastWifi.aps.map(a=>{
        const nc=lastWifi.clients.filter(c=>c.bssid===a.bssid).length;
        const active=parseInt(a.data||"0",10)>0;
        return {addr:a.bssid, label:a.essid, wifi:true, active, ap:a,
          sub:`ch ${a.channel} · ${a.power}dBm · ${a.enc} · ${active?("▲ "+a.data+" data"):"idle"}${nc?(" · "+nc+" clients"):""}`};
      });
      selected=null; renderHosts();
      write(`found ${d.count} access point${d.count===1?"":"s"} on ${d.iface}. tap one for details.\n`);
      if(d.iface){ wlanMon=d.iface; renderWifiNote(); }
      write(`\nrestore managed mode when done: airmon-ng stop ${d.iface||wlanMon||"wlan0mon"} && systemctl restart NetworkManager\n`);
    }
  }catch(e){ if(e.name!=="AbortError"){ cursor(false); write("[error] "+e.message+"\n"); } }
  finally{ if(g===gen) setRunning(false); }
}

function showAPDetails(){
  if(selected===null || !hosts[selected].wifi){ showToast("select an access point"); return; }
  const a=hosts[selected].ap;
  const cl=lastWifi.clients.filter(c=>c.bssid===a.bssid);
  out.textContent="";
  write(`ACCESS POINT  ${a.essid}\n`,"cmd");
  write(`  bssid     ${a.bssid}\n  channel   ${a.channel}\n  signal    ${a.power} dBm\n  encrypt   ${a.enc}\n  beacons   ${a.beacons}\n  data      ${a.data}  ${parseInt(a.data||"0",10)>0?"(active traffic)":"(idle)"}\n\n`);
  write(`ASSOCIATED CLIENTS (${cl.length})\n`,"cmd");
  if(cl.length) cl.forEach(c=>write(`  ${c.station}   ${c.power}dBm   ${c.packets} pkts\n`));
  else write("  (none seen during this capture)\n");
}

async function pipe(r){
  const rd=r.body.getReader(), dec=new TextDecoder(); let first=true, buf="";
  while(true){ const {done,value}=await rd.read(); if(done)break;
    const chunk=dec.decode(value,{stream:true});
    cursor(false); write(chunk, first?"cmd":null); first=false; cursor(true);
    buf=(buf+chunk).slice(-2500); parseProgress(buf); }
  cursor(false);
}

function renderPorts(){
  const bar=$("#ports");
  const re=/^\s*(\d+)\/(tcp|udp)\s+(\S+)/gm; let m, seen={}, list=[];
  const txt=out.textContent;
  while((m=re.exec(txt))){ const k=m[1]+"/"+m[2]; if(!seen[k]){ seen[k]=1; list.push({port:m[1],svc:m[3]}); } }
  if(!list.length){ clearPorts(); return; }
  bar.style.display="";
  bar.innerHTML = `<span class="portlbl">dig deeper:</span>`+
    list.map(p=>`<button class="port" data-port="${esc(p.port)}" data-svc="${esc(p.svc)}">${esc(p.port)} ${esc(p.svc)}</button>`).join("");
}

async function digPort(port, svc){
  if(running || !scanHost) return;
  called=true;
  setRunning(true);
  out.textContent=""; cursor(true);
  ctrl=new AbortController();
  let endPhase="complete";
  try{
    const r=await fetch("/api/port_scan",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({target:scanHost,port,service:svc||"",stealth}),signal:ctrl.signal});
    await pipe(r); endPhase=r.ok?"complete":"error";
  }catch(e){ cursor(false);
    if(e.name!=="AbortError"){ write("\n[error] "+e.message+"\n"); endPhase="error"; }
    else { write("\n[aborted]\n"); endPhase="aborted"; } }
  finally{ setRunning(false); setPhase(endPhase,false); renderPorts(); }
}

async function runScan(scanId){
  if(running || selected===null){ if(selected===null) showToast("select a target first"); return; }
  profile=scanId; renderTabs();
  called=true;
  setRunning(true);
  out.textContent=""; clearPorts(); cursor(true);
  ctrl=new AbortController();
  let endPhase="complete";
  const bt = hosts[selected].bt;
  scanHost = hosts[selected].addr;
  const ep = bt ? "/api/bt_scan" : "/api/scan";
  try{
    const r=await fetch(ep,{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({scan:scanId,target:hosts[selected].addr,stealth}),signal:ctrl.signal});
    await pipe(r); endPhase=r.ok?"complete":"error";
  }catch(e){ cursor(false);
    if(e.name!=="AbortError"){ write("\n[error] "+e.message+"\n"); endPhase="error"; }
    else { write("\n[aborted]\n"); endPhase="aborted"; } }
  finally{ setRunning(false); setPhase(endPhase, false); if(!bt) renderPorts(); }
}

async function launchTool(id){
  showToast("launching "+id+"…");
  try{
    const r=await fetch("/api/launch",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({tool:id})});
    const d=await r.json();
    showToast(d.ok ? d.launched+" opened in a terminal" : "error: "+d.error);
  }catch(e){ showToast("error: "+e.message); }
}

document.addEventListener("click",e=>{
  const md=e.target.closest("[data-mode]");    if(md){ setMode(md.dataset.mode); return; }
  const portc=e.target.closest("[data-port]");  if(portc){ digPort(+portc.dataset.port, portc.dataset.svc); return; }
  const host=e.target.closest("[data-i]");      if(host){ selectHost(+host.dataset.i); return; }
  const tab=e.target.closest("[data-scan]");    if(tab){ runScan(tab.dataset.scan); return; }
  const tool=e.target.closest("[data-tool]");   if(tool){ launchTool(tool.dataset.tool); return; }
  const um=e.target.closest("[data-um]");      if(um){ setUiMode(um.dataset.um); setPref("ui",um.dataset.um); return; }
  if(e.target.closest("#gear")){ openSettings(); return; }
  if(e.target.closest("#setclose")){ closeSettings(); return; }
  if(e.target.closest("#setsave")){ saveSettings(); return; }
  if(e.target.id==="settings"){ closeSettings(); return; }
  if(e.target.closest("#rescan")){ discoverWifi(); return; }
  if(e.target.closest("#details")){ showAPDetails(); return; }
  if(e.target.closest("#bigcall")){
    if(running){ if(ctrl)ctrl.abort(); }
    else if(selected===null){ discover(); }
    else { runScan(profile); }
    return;
  }
  if(e.target.closest("#discover")){ discover(); return; }
  if(e.target.closest("#abort")){ if(ctrl)ctrl.abort(); return; }
  if(e.target.closest("#stealth")){
    stealth=!stealth;
    const b=$("#stealth"); b.classList.toggle("on",stealth);
    b.textContent = stealth ? "STEALTH ON" : "STEALTH OFF";
    showToast(stealth ? "stealth on — scans use a random MAC" : "stealth off");
    return;
  }
});

$("#gear").innerHTML = I('gear',20);
$("#set-prof").innerHTML = NET_SCANS.map(s=>`<option value="${s.id}">${s.en}</option>`).join("");
loadPrefs();
renderTabs();
renderRail();
renderCard();
updateCallScreen();
loadConfig();
</script>
</body>
</html>"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DokkOS — interactive local recon console",
        epilog="examples:\n"
               "  python app.py                       # auto-detect local networks\n"
               "  python app.py 10.0.0.0/24           # one network\n"
               "  python app.py 192.168.0.0/16 10.0.0.0/24 scanme.nmap.org\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="*",
                        help="networks/hosts to make scannable (CIDR, IP, or hostname). "
                             "Default: auto-detect every network this host is on.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default 127.0.0.1 — keep it local)")
    parser.add_argument("--port", type=int, default=5000, help="port (default 5000)")
    parser.add_argument("--wlan-mon", dest="wlan_mon", default=None,
                        help="monitor-mode wireless interface for Wi-Fi recon "
                             "(e.g. wlan0mon). Default: auto-detect.")
    parser.add_argument("--install", action="store_true",
                        help="install any missing tools (apt + pip), then continue. "
                             "Needs root for apt — run with sudo.")
    parser.add_argument("--check", action="store_true",
                        help="report which tools are present/missing and exit.")
    args = parser.parse_args()

    present, miss_apt, miss_pip = check_dependencies()
    if args.check:
        print("present:", ", ".join(present) or "(none)")
        print("missing apt:", " ".join(miss_apt) or "(none)")
        print("missing pip:", " ".join(miss_pip) or "(none)")
        raise SystemExit(0)
    if args.install:
        install_dependencies()
    elif miss_apt or miss_pip:
        print("[deps] missing:", " ".join(miss_apt + miss_pip),
              "— run with --install to set them up.")

    if args.wlan_mon:
        WIFI_MON = args.wlan_mon

    chosen = []
    for t in args.targets:
        v = validate_target(t)
        if v:
            chosen.append(v)
        else:
            print(f"[skip] invalid target: {t}")
    if not chosen:
        chosen = detect_local_networks()
        if chosen:
            print("[auto] detected local networks:", ", ".join(chosen))
    if not chosen:
        chosen = ["192.168.1.0/24"]
        print("[warn] couldn't auto-detect networks; defaulting to 192.168.1.0/24")
        print("       pass explicit targets, e.g.: python app.py 10.0.0.0/24")
    SCAN_TARGETS[:] = chosen
    print("Scan scopes:", ", ".join(SCAN_TARGETS))

    try:
        loopback = ipaddress.ip_address(args.host).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        print("\n" + "!" * 64)
        print(f"[WARNING] binding to {args.host}, not loopback.")
        print("  DokkOS has NO authentication and can run scans and launch tools")
        print("  (often as root). Anyone who can reach this address can drive it.")
        print("  Only do this on a trusted, isolated network — otherwise use 127.0.0.1.")
        print("!" * 64 + "\n")

    print(f"DokkOS on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, threaded=True)
