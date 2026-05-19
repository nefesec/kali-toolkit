"""Reconnaissance — 8 outils."""

from core import ui, runner


def nmap_quick():
    ui.header("Nmap — scan rapide (top 100 ports)")
    target = ui.ask("cible (IP ou domaine)")
    if not target: return
    runner.run(["nmap", "-F", "-T4", target], tag="nmap-quick")
    ui.pause()


def nmap_full():
    ui.header("Nmap — scan complet + détection services/OS")
    if not runner.check_tools(["nmap"]): ui.pause(); return
    target = ui.ask("cible")
    if not target: return
    runner.run(["nmap", "-sS", "-sV", "-O", "-p-", "-T4", target], tag="nmap-full", root=True)
    ui.pause()


def nmap_vuln():
    ui.header("Nmap — scripts de vulnérabilités")
    target = ui.ask("cible")
    if not target: return
    runner.run(["nmap", "--script", "vuln", "-sV", target], tag="nmap-vuln")
    ui.pause()


def nmap_stealth():
    ui.header("Nmap — scan furtif (SYN, slow, decoy)")
    target = ui.ask("cible")
    if not target: return
    runner.run(["nmap", "-sS", "-T2", "-f", "-D", "RND:5", target], tag="nmap-stealth", root=True)
    ui.pause()


def whois_lookup():
    ui.header("WHOIS — info domaine")
    if not runner.check_tools(["whois"]): ui.pause(); return
    target = ui.ask("domaine")
    if not target: return
    runner.run(["whois", target], tag="whois")
    ui.pause()


def dnsrecon():
    ui.header("dnsrecon — énumération DNS")
    if not runner.check_tools(["dnsrecon"]): ui.pause(); return
    target = ui.ask("domaine")
    if not target: return
    runner.run(["dnsrecon", "-d", target, "-t", "std"], tag="dnsrecon")
    ui.pause()


def theharvester():
    ui.header("theHarvester — OSINT emails/sous-domaines")
    binary = "theHarvester" if runner.need_tool("theHarvester") else "theharvester"
    if not runner.need_tool(binary):
        ui.err("theHarvester introuvable — sudo apt install theharvester"); ui.pause(); return
    target = ui.ask("domaine")
    if not target: return
    runner.run([binary, "-d", target, "-b", "all", "-l", "200"], tag="harvester")
    ui.pause()


def whatweb():
    ui.header("WhatWeb — fingerprint tech web")
    if not runner.check_tools(["whatweb"]): ui.pause(); return
    target = ui.ask("URL (ex: https://example.com)")
    if not target: return
    runner.run(["whatweb", "-v", target], tag="whatweb")
    ui.pause()


ITEMS = [
    {
        "label": "Nmap — scan rapide (top 100)",
        "fn": nmap_quick, "status": "ok",
        "info": """Scan TCP des 100 ports les plus fréquents en mode SYN furtif (-T4 rapide).

QUAND       : première phase, voir vite ce qui est exposé
PRÉREQUIS   : aucun (root améliore via SYN scan -sS)
SORTIE      : ports OPEN/CLOSED/FILTERED + service deviné
EXEMPLES    : nmap -F 192.168.1.1 / nmap -F scanme.nmap.org
TIPS        : si rien ne sort = FW drop ICMP → ajouter -Pn
LIMITES     : rate logged par tous les IDS modernes (T4=bruyant)"""
    },
    {
        "label": "Nmap — scan complet + OS",
        "fn": nmap_full, "status": "ok",
        "info": """Scan TOUS les ports (1-65535) + détection version + OS fingerprint.

QUAND       : après le scan rapide, pour vue exhaustive
PRÉREQUIS   : sudo (SYN scan + OS fingerprint)
DURÉE       : 5-30 min selon cible
SORTIE      : services avec version, OS deviné, tous ports
TIPS        : ajouter -oA basename pour sauver en 3 formats
LIMITES     : très bruyant, sera bloqué par bons WAF/IDS"""
    },
    {
        "label": "Nmap — scripts vulnérabilités",
        "fn": nmap_vuln, "status": "cfg",
        "info": """Lance les scripts NSE catégorie 'vuln' sur la cible.

QUAND       : après détection des services, pour CVE rapides
PRÉREQUIS   : aucun
SORTIE      : alertes 'VULNERABLE' avec CVE associées
TIPS        : combiner avec searchsploit pour PoC : 'searchsploit <produit>'
LIMITES     : ne trouve QUE les vulns avec script NSE existant
              (cherche CVE-* dans la sortie, le reste = négatif)
              Faux positifs fréquents sur HTTPS mal configuré"""
    },
    {
        "label": "Nmap — scan furtif",
        "fn": nmap_stealth, "status": "cfg",
        "info": """SYN scan slow (-T2) + fragments (-f) + 5 leurres IP aléatoires (-D).

QUAND       : cible avec IDS/IPS suspecté, blue team active
PRÉREQUIS   : sudo
DURÉE       : long (T2 = ~1 paquet/15s)
TIPS        : combiner avec spoof MAC : 'macchanger -r eth0'
LIMITES     : un IDS moderne (Suricata, Zeek) détecte quand même
              Vrai 'silence' = scan via Tor ou depuis cible interne"""
    },
    {
        "label": "WHOIS — info domaine",
        "fn": whois_lookup, "status": "ok",
        "info": """Récupère les infos publiques d'un domaine ou IP.

QUAND       : phase OSINT initiale
SORTIE      : registrar, dates expiration, contact, NS, organisation
TIPS        : utile pour deviner emails admin (admin@, contact@)
LIMITES     : RGPD masque les contacts perso depuis 2018 (.fr/.eu)
              Pour les .com encore quelques infos visibles"""
    },
    {
        "label": "dnsrecon — énumération DNS",
        "fn": dnsrecon, "status": "ok",
        "info": """Énumère les enregistrements DNS d'un domaine (A, AAAA, MX, NS, TXT, SRV).

QUAND       : trouver sous-domaines + serveurs mail/admin
SORTIE      : tous les records DNS + tentative AXFR (transfert de zone)
TIPS        : si AXFR réussit = jackpot (tous sous-domaines révélés)
              Combiner avec sublist3r ou amass pour brute sous-domaines
LIMITES     : limité aux records publics. Pour sous-domaines cachés
              utiliser bruteforce de sous-domaines (sublist3r/amass)"""
    },
    {
        "label": "theHarvester — OSINT emails",
        "fn": theharvester, "status": "ok",
        "info": """Récupère emails + noms + sous-domaines via Google/Bing/LinkedIn/etc.

QUAND       : préparer phishing ou password spray
SORTIE      : liste emails @cible.com, employés trouvés
TIPS        : 'all' = toutes sources mais lent → essayer 'google,bing,duckduckgo'
              Émetteurs souvent dans X-Originating-IP des mails reçus
LIMITES     : Google rate-limit agressif → API keys nécessaires pour gros volume
              Beaucoup de sources nécessitent abonnement (Shodan, Hunter.io)"""
    },
    {
        "label": "WhatWeb — fingerprint web",
        "fn": whatweb, "status": "ok",
        "info": """Identifie la stack technique d'un site web (CMS, framework, JS libs, serveur).

QUAND       : avant attaque web pour cibler les bons exploits
SORTIE      : Apache 2.4.41 / WordPress 6.0 / jQuery 3.6 / etc.
TIPS        : si WordPress détecté → WPScan pour énumérer plugins vulnérables
              Si version vieille → searchsploit
LIMITES     : sites cachant version (header Server: nginx) ne donnent rien
              WAF (Cloudflare/Akamai) masquent souvent le vrai serveur"""
    },
]


def menu():
    while True:
        idx = ui.menu("RECONNAISSANCE", ITEMS)
        if idx is None: return
        ITEMS[idx]["fn"]()
