"""Web — 6 outils."""

from core import ui, runner


def dirb_scan():
    ui.header("Dirb — bruteforce répertoires")
    if not runner.check_tools(["dirb"]): ui.pause(); return
    url = ui.ask("URL"); wl = ui.ask("wordlist", default="/usr/share/wordlists/dirb/common.txt")
    if not url: ui.pause(); return
    runner.run(["dirb", url, wl], tag="dirb"); ui.pause_with_analysis()


def gobuster_scan():
    ui.header("Gobuster — bruteforce répertoires (rapide)")
    if not runner.check_tools(["gobuster"]): ui.pause(); return
    url = ui.ask("URL"); wl = ui.ask("wordlist", default="/usr/share/wordlists/dirb/common.txt")
    if not url: ui.pause(); return
    runner.run(["gobuster", "dir", "-u", url, "-w", wl, "-t", "50"], tag="gobuster"); ui.pause_with_analysis()


def nikto_scan():
    ui.header("Nikto — scan vulnérabilités web")
    if not runner.check_tools(["nikto"]): ui.pause(); return
    url = ui.ask("URL")
    if not url: ui.pause(); return
    runner.run(["nikto", "-h", url], tag="nikto"); ui.pause_with_analysis()


def sqlmap_scan():
    ui.header("sqlmap — injection SQL")
    if not runner.check_tools(["sqlmap"]): ui.pause(); return
    url = ui.ask("URL avec paramètre (ex: http://x/p?id=1)")
    if not url: ui.pause(); return
    runner.run(["sqlmap", "-u", url, "--batch", "--level=2"], tag="sqlmap"); ui.pause_with_analysis()


def wpscan_scan():
    ui.header("WPScan — audit WordPress")
    if not runner.check_tools(["wpscan"]): ui.pause(); return
    url = ui.ask("URL WordPress")
    if not url: ui.pause(); return
    runner.run(["wpscan", "--url", url, "--enumerate", "vp,vt,u", "--random-user-agent"],
               tag="wpscan"); ui.pause_with_analysis()


def xss_test():
    ui.header("XSStrike — XSS")
    if not runner.check_tools(["xsstrike"]):
        ui.warn("xsstrike absent — sudo apt install xsstrike"); ui.pause(); return
    url = ui.ask("URL avec paramètre")
    if not url: ui.pause(); return
    runner.run(["xsstrike", "-u", url], tag="xsstrike"); ui.pause()


ITEMS = [
    {
        "label": "Dirb — bruteforce dirs", "fn": dirb_scan, "status": "ok",
        "info": """Teste l'existence de répertoires/fichiers courants via wordlist.

QUAND       : après whatweb, pour trouver fichiers cachés (.git, admin/, backup.zip)
SORTIE      : URLs avec code HTTP 200/301/403
TIPS        : codes 403 souvent = dossier existe mais accès restreint = intéressant
              Wordlists Kali : /usr/share/wordlists/dirb/big.txt (~20k mots)
LIMITES     : lent (mono-thread). Préférer gobuster pour vrais tests
              Beaucoup de 200 = false positives sur sites avec catch-all"""
    },
    {
        "label": "Gobuster — bruteforce dirs", "fn": gobuster_scan, "status": "ok",
        "info": """Idem dirb mais en Go, multi-thread (50 par défaut).

QUAND       : préférer à dirb sur cibles permettant le débit
SORTIE      : URLs trouvées avec code HTTP + taille
TIPS        : -x php,html,txt pour aussi tester ces extensions
              Mode 'dns' pour bruteforce sous-domaines :
              gobuster dns -d example.com -w wordlist.txt
LIMITES     : rate-limit côté serveur peut bannir ton IP → ralentir avec --delay"""
    },
    {
        "label": "Nikto — vuln scan", "fn": nikto_scan, "status": "old",
        "info": """Scanner historique de vulnérabilités web (>6700 tests connus).

QUAND       : audit rapide, bonne base de découverte
SORTIE      : fichiers exposés, headers manquants, versions vulnérables, CVE
LIMITES (RAISON STATUT 'VIEUX') :
  - Base de tests datée (focus apps anciennes)
  - Très bruyant → User-Agent 'Nikto' détecté en 1s par tout WAF
  - Beaucoup de false positives
  - Pour audit moderne : Burp Pro / OWASP ZAP / wapiti à privilégier
ENCORE UTILE: petits CMS perso, vieux serveurs intranet"""
    },
    {
        "label": "sqlmap — SQL injection", "fn": sqlmap_scan, "status": "ok",
        "info": """Teste l'injection SQL sur tous les paramètres + dump base.

QUAND       : URL avec paramètre suspect (id=, page=, sort=, search=)
NIVEAUX     : --level 1-5 (essais), --risk 1-3 (DESTRUCTIF si 3)
DUMP        : --dbs / -D base --tables / -D base -T table --dump
TIPS        : auth requise → --cookie="PHPSESSID=..." ou --data="user=a&pwd=b"
              --tamper=between : bypass certains WAFs
LIMITES     : ne trouve PAS les blind SQLi très subtiles (boolean second-order)
              Bloqué par WAF moderne (Cloudflare WAF, Akamai) sans tampers"""
    },
    {
        "label": "WPScan — audit WordPress", "fn": wpscan_scan, "status": "ok",
        "info": """Énumère version WordPress, thèmes, plugins, users, et leurs vulnérabilités connues.

QUAND       : whatweb a révélé WordPress
SORTIE      : version WP + plugins + CVE par plugin + users (login bruteforce ready)
TIPS        : pour activer la DB de vulns : --api-token <token> (gratuit sur wpscan.com)
              Bruteforce user trouvé : --usernames admin --passwords rockyou.txt
LIMITES     : sans API token, pas de check CVE plugins
              Sites avec security plugins (Wordfence, iThemes) détectent/bloquent"""
    },
    {
        "label": "XSStrike — test XSS", "fn": xss_test, "status": "cfg",
        "info": """Test automatisé d'injection XSS (DOM, réfléchie, stockée) avec bypass WAF.

QUAND       : URL avec champs reflétés (search?q=, comment, form data)
SORTIE      : payload qui pop alert + contexte d'injection
LIMITES     : tests automatiques limités sur XSS DOM complexes
              Pour bug bounty sérieux → analyse manuelle + Burp"""
    },
]


def menu():
    while True:
        idx = ui.menu("WEB", ITEMS)
        if idx is None: return
        ITEMS[idx]["fn"]()
