"""Analyse post-attaque : extrait les données chopées, priorise, suggère la suite."""

import os
import re
import glob
import base64
import subprocess
from core import ui

LOG_DIR = os.path.expanduser("~/.kt-logs")

# Patterns d'extraction
P = {
    "http_basic":  re.compile(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)'),
    "cookie":      re.compile(r'(?:Cookie|Set-Cookie):\s*([\w-]+)=([^\s;]+)'),
    "form_creds":  re.compile(r'(?i)(?:user|email|login|password|pwd|pass)=([^\s&"\']{2,80})'),
    "ftp_user":    re.compile(r'USER\s+(\S+)', re.IGNORECASE),
    "ftp_pass":    re.compile(r'PASS\s+(\S+)', re.IGNORECASE),
    "ssh_pass":    re.compile(r'sshd.*?Accepted password for (\S+) from (\S+)'),
    "email":       re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
    "ipv4":        re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "url":         re.compile(r'https?://[^\s<>"\']+'),
    "privkey":     re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
    "aws_key":     re.compile(r'AKIA[0-9A-Z]{16}'),
    "github_pat":  re.compile(r'ghp_[A-Za-z0-9]{30,}'),
    "jwt":         re.compile(r'eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+'),
    "nmap_open":   re.compile(r'^(\d+)/(\w+)\s+open\s+([^\s]+)(?:\s+(.+))?', re.MULTILINE),
    "wpa_hs":      re.compile(r'WPA handshake[:\s]*([0-9A-Fa-f:]{17})'),
    "pmkid":       re.compile(r'(?i)PMKID.*found|PMKID.*captured'),
    "ssid_found":  re.compile(r'^\s*([0-9A-Fa-f:]{17})\s+\S+\s+(\d+)\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+(.+)$', re.MULTILINE),
    "dirb_hit":    re.compile(r'(?:==> DIRECTORY|CODE:200|CODE:301|CODE:403):?\s*(\S+)'),
    "nikto_vuln":  re.compile(r'\+ /.*: .+'),
}

# Ports d'intérêt + suggestion d'attaque suivante
CRITICAL_PORTS = {
    21:   ("FTP",         "Hydra FTP / login anonymous"),
    22:   ("SSH",         "Hydra SSH (souvent rate-limited)"),
    23:   ("Telnet",      "Capture passive — auth CLEAR TEXT"),
    25:   ("SMTP",        "User enum (VRFY/EXPN)"),
    53:   ("DNS",         "dnsrecon zone transfer"),
    80:   ("HTTP",        "whatweb → dirb → nikto"),
    110:  ("POP3",        "Hydra POP3 (auth clear)"),
    111:  ("RPC",         "rpcinfo -p — souvent NFS derrière"),
    135:  ("MSRPC",       "Windows — impacket-rpcdump"),
    139:  ("NetBIOS",     "smbclient -L //IP"),
    143:  ("IMAP",        "Hydra IMAP"),
    161:  ("SNMP",        "onesixtyone / snmpwalk public/private"),
    389:  ("LDAP",        "ldapsearch anonymous bind"),
    443:  ("HTTPS",       "whatweb / nikto -ssl"),
    445:  ("SMB",         "enum4linux / smbclient / EternalBlue check"),
    993:  ("IMAPS",       "Hydra IMAPS"),
    1433: ("MSSQL",       "sqlmap / mssqlclient.py"),
    2049: ("NFS",         "showmount -e / mount"),
    3306: ("MySQL",       "Hydra MySQL / sqlmap"),
    3389: ("RDP",         "Hydra RDP / BlueKeep check"),
    5432: ("PostgreSQL",  "Hydra postgres"),
    5900: ("VNC",         "Souvent sans auth — vncviewer"),
    6379: ("Redis",       "redis-cli unauthenticated"),
    8080: ("HTTP-alt",    "Admin panel souvent ici"),
    9200: ("Elasticsearch","souvent open — curl /_cat/indices"),
    27017:("MongoDB",     "souvent open — mongo --eval"),
}

INTERESTING_COOKIES = ("session", "phpsessid", "jsessionid", "auth", "token", "sessid", "_csrf", "remember")
INTERESTING_PATHS = ("admin", "login", "wp-admin", "config", ".git", ".env", "backup", "phpinfo", "api", ".bak", ".sql")


# ─────────────────────────────────────────────────────────────────────────────
# EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def analyze(content):
    """Retourne dict findings par sévérité."""
    f = {"critical": [], "high": [], "medium": [], "low": [], "info": []}

    # CRITIQUE — credentials clair-texte
    for m in P["http_basic"].finditer(content):
        try:
            decoded = base64.b64decode(m.group(1)).decode(errors="ignore")
            f["critical"].append(f"HTTP Basic Auth (clair) : {decoded}")
        except Exception:
            pass

    users = P["ftp_user"].findall(content)
    pwds  = P["ftp_pass"].findall(content)
    for u, p in zip(users, pwds):
        f["critical"].append(f"FTP creds capturés : {u} / {p}")

    for m in P["ssh_pass"].finditer(content):
        f["critical"].append(f"SSH auth réussi : {m.group(1)} @ {m.group(2)}")

    if P["privkey"].search(content):
        f["critical"].append("CLÉ PRIVÉE TROUVÉE dans le trafic !")

    for m in P["aws_key"].finditer(content):
        f["critical"].append(f"AWS Access Key : {m.group(0)}")

    for m in P["github_pat"].finditer(content):
        f["critical"].append(f"GitHub PAT : {m.group(0)[:20]}...")

    # ÉLEVÉ — tokens, ports juteux, dirs sensibles
    for m in P["jwt"].finditer(content):
        f["high"].append(f"JWT capturé : {m.group(0)[:60]}...")

    cookies_done = set()
    for m in P["cookie"].finditer(content):
        name, val = m.group(1), m.group(2)
        if name.lower() in INTERESTING_COOKIES and name not in cookies_done:
            f["high"].append(f"Cookie session : {name}={val[:40]}{'...' if len(val) > 40 else ''}")
            cookies_done.add(name)

    # Form creds capturés
    for m in P["form_creds"].finditer(content):
        val = m.group(1)
        if 4 <= len(val) <= 60 and val.lower() not in ("true", "false", "null"):
            f["high"].append(f"Form parameter : {val[:50]}")

    # Nmap ports
    seen_ports = set()
    for m in P["nmap_open"].finditer(content):
        port = int(m.group(1))
        if port in seen_ports: continue
        seen_ports.add(port)
        proto = m.group(2)
        svc = m.group(3)
        version = (m.group(4) or "").strip()
        suffix = f" ({version})" if version else ""
        if port in CRITICAL_PORTS:
            label, suggestion = CRITICAL_PORTS[port]
            f["high"].append(f"Port {port}/{proto} → {label}{suffix}  ⇒ {suggestion}")
        else:
            f["medium"].append(f"Port {port}/{proto} {svc}{suffix}")

    # WiFi captures
    for m in P["wpa_hs"].finditer(content):
        f["high"].append(f"WPA handshake CAPTURÉ pour {m.group(1)} → crack offline possible")

    if P["pmkid"].search(content):
        f["high"].append("PMKID capturé → convertir avec hcxpcapngtool + hashcat -m 22000")

    # Web — endpoints suspects
    for m in P["dirb_hit"].finditer(content):
        path = m.group(1)
        if any(k in path.lower() for k in INTERESTING_PATHS):
            f["high"].append(f"Endpoint sensible : {path}")
        else:
            f["medium"].append(f"Endpoint trouvé : {path}")

    # nikto findings (lignes commençant par "+ /")
    nikto_hits = P["nikto_vuln"].findall(content)
    for line in nikto_hits[:20]:
        line = line.strip()
        if any(k in line.lower() for k in ("admin", "config", "backup", "default", ".git", "phpinfo", "shell")):
            f["high"].append(f"Nikto : {line[:150]}")
        else:
            f["medium"].append(f"Nikto : {line[:150]}")

    # INFO — emails (utile phishing/password spray)
    emails = sorted(set(P["email"].findall(content)))
    if emails:
        f["info"].append(f"{len(emails)} emails uniques :")
        for e in emails[:15]:
            f["info"].append(f"  • {e}")
        if len(emails) > 15:
            f["info"].append(f"  ... +{len(emails)-15} autres")

    # IPs uniques
    ips = sorted(set(P["ipv4"].findall(content)))
    if 0 < len(ips) <= 30:
        f["low"].append(f"{len(ips)} IPs distinctes : {', '.join(ips[:10])}{'...' if len(ips) > 10 else ''}")
    elif len(ips) > 30:
        f["low"].append(f"{len(ips)} IPs distinctes (trop pour lister)")

    # URLs
    urls = set(P["url"].findall(content))
    if urls:
        f["low"].append(f"{len(urls)} URLs uniques visitées/référencées")

    return f


# ─────────────────────────────────────────────────────────────────────────────
# AFFICHAGE
# ─────────────────────────────────────────────────────────────────────────────

def display(findings, source_file):
    total = sum(len(v) for v in findings.values())
    ui.header(f"Findings — {os.path.basename(source_file)}")

    if total == 0:
        ui.warn("Aucune donnée intéressante extraite.")
        return

    ui.ok(f"{total} éléments extraits\n")

    severities = [
        ("critical", ui.R, "CRITIQUE"),
        ("high",     ui.Y, "ÉLEVÉ"),
        ("medium",   ui.C, "MOYEN"),
        ("low",      ui.D, "FAIBLE"),
        ("info",     ui.G, "INFO"),
    ]
    for key, color, label in severities:
        items = findings[key]
        if not items: continue
        bar = "━" * (len(label) + 8)
        print(f"\n{color}{ui.BOLD}{bar}{ui.RESET}")
        print(f"{color}{ui.BOLD}  {label} ({len(items)}){ui.RESET}")
        print(f"{color}{ui.BOLD}{bar}{ui.RESET}\n")
        for it in items:
            print(f"  {color}▸{ui.RESET} {it}")


def suggest(findings):
    """Propose les prochaines attaques selon ce qui a été trouvé."""
    flat = " ".join(sum(findings.values(), [])).lower()
    suggestions = []

    if "ftp" in flat:
        suggestions.append("Hydra FTP bruteforce → kt.py → Exploitation → Hydra FTP")
    if "ssh" in flat and "port 22" in flat:
        suggestions.append("Hydra SSH bruteforce → kt.py → Exploitation → Hydra SSH")
    if "smb" in flat or " 445" in flat:
        suggestions.append("SMB enum : enum4linux -a <IP> / smbclient -L //<IP>")
        suggestions.append("Test EternalBlue : msfconsole → use exploit/windows/smb/ms17_010_eternalblue")
    if "telnet" in flat or " 23/" in flat:
        suggestions.append("Telnet = creds en clair → tcpdump -A 'port 23'")
    if "wpa handshake" in flat:
        suggestions.append("Crack handshake : aircrack-ng -w rockyou.txt capture.cap")
        suggestions.append("ou GPU plus rapide : hashcat -m 22000 hash.hc22000 wordlist.txt")
    if "pmkid" in flat:
        suggestions.append("hcxpcapngtool -o hash.hc22000 capture.pcapng && hashcat -m 22000 hash.hc22000 rockyou.txt")
    if "session" in flat or "jwt" in flat or "cookie" in flat:
        suggestions.append("Session hijack : importer le cookie/JWT dans Burp ou navigateur (DevTools → Application → Cookies)")
    if "clé privée" in flat or "private key" in flat:
        suggestions.append("ssh -i <fichier_clé> user@<host> — essaie sur tous les hosts du scan")
    if "wordpress" in flat:
        suggestions.append("WPScan complet : kt.py → Web → WPScan")
    if "phpinfo" in flat or ".git" in flat:
        suggestions.append("Endpoint exposé — récupérer manuellement : curl <url>/.git/config / phpinfo.php")
    if any(p in flat for p in (" 80/", " 443/", "http://", "https://")):
        suggestions.append("Énum web : kt.py → Web → dirb/gobuster + Nikto")
    if "redis" in flat:
        suggestions.append("Redis sans auth : redis-cli -h <IP> → 'info' / 'keys *'")
    if "mongo" in flat:
        suggestions.append("MongoDB : mongo <IP>:27017 → 'show dbs'")
    if "elasticsearch" in flat:
        suggestions.append("ES : curl <IP>:9200/_cat/indices")

    if suggestions:
        print(f"\n{ui.M}{ui.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{ui.RESET}")
        print(f"{ui.M}{ui.BOLD}  PROCHAINES ÉTAPES SUGGÉRÉES{ui.RESET}")
        print(f"{ui.M}{ui.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{ui.RESET}\n")
        for s in suggestions:
            print(f"  {ui.M}→{ui.RESET} {s}")


# ─────────────────────────────────────────────────────────────────────────────
# MENU
# ─────────────────────────────────────────────────────────────────────────────

def _read(path):
    if path.endswith((".pcap", ".cap", ".pcapng")):
        try:
            return subprocess.check_output(
                ["tshark", "-r", path, "-Y", "http or ftp or telnet or dns", "-x"],
                text=True, errors="ignore", stderr=subprocess.DEVNULL, timeout=30
            )
        except Exception:
            return ""
    try:
        with open(path, errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def analyze_latest():
    ui.header("Analyse — dernier log")
    if not os.path.isdir(LOG_DIR):
        ui.err(f"{LOG_DIR} n'existe pas"); ui.pause(); return
    files = sorted(glob.glob(os.path.join(LOG_DIR, "*")), key=os.path.getmtime, reverse=True)
    if not files:
        ui.err("aucun log"); ui.pause(); return
    path = files[0]
    ui.info(f"fichier : {path}\n")
    content = _read(path)
    if not content:
        ui.warn("fichier vide ou illisible"); ui.pause(); return
    findings = analyze(content)
    display(findings, path)
    suggest(findings)
    ui.pause()


def analyze_file():
    ui.header("Analyse — fichier au choix")
    path = ui.ask("chemin du fichier (.log/.pcap/.txt)")
    if not path or not os.path.exists(path):
        ui.err("introuvable"); ui.pause(); return
    content = _read(path)
    findings = analyze(content)
    display(findings, path)
    suggest(findings)
    ui.pause()


def list_recent():
    ui.header("Logs récents (~/.kt-logs)")
    if not os.path.isdir(LOG_DIR):
        ui.err(f"{LOG_DIR} n'existe pas"); ui.pause(); return
    files = sorted(glob.glob(os.path.join(LOG_DIR, "*")), key=os.path.getmtime, reverse=True)[:20]
    if not files:
        ui.warn("aucun log"); ui.pause(); return
    for path in files:
        size = os.path.getsize(path)
        size_str = f"{size:,}" if size < 1_000_000 else f"{size/1024/1024:.1f} Mo"
        name = os.path.basename(path)
        print(f"  {ui.D}{size_str:>12}{ui.RESET}  {name}")
    ui.pause()


ITEMS = [
    {
        "label": "Analyser le DERNIER log/capture", "fn": analyze_latest, "status": "tool",
        "info": """Lit le fichier le plus récent de ~/.kt-logs/ et extrait automatiquement :

CRITIQUE     : credentials clair, clés privées, AWS keys, GitHub PAT
ÉLEVÉ        : tokens JWT, cookies session, ports juteux (SMB/RDP/SSH), handshakes WPA
MOYEN        : ports moins critiques, endpoints découverts
FAIBLE       : IPs et URLs vues
INFO         : emails uniques (utile phishing/spray)

À la fin → SUGGÈRE concrètement la prochaine attaque selon ce qui a été trouvé.

EXEMPLES :
  Port 445 vu  → "test EternalBlue : msfconsole → ms17_010"
  WPA handshake → "aircrack-ng -w rockyou.txt capture.cap"
  Cookie session → "importer dans Burp pour hijack"
"""
    },
    {
        "label": "Analyser un fichier spécifique", "fn": analyze_file, "status": "tool",
        "info": """Analyse un fichier .log / .pcap / .cap / .txt au choix.

Pour les .pcap : utilise tshark pour extraire le trafic intéressant (HTTP/FTP/DNS/telnet)
avant analyse pattern."""
    },
    {
        "label": "Lister les 20 logs récents", "fn": list_recent, "status": "tool",
        "info": """Affiche les 20 derniers fichiers dans ~/.kt-logs/ avec leur taille."""
    },
]


def menu():
    while True:
        idx = ui.menu("ANALYSE POST-ATTAQUE", ITEMS)
        if idx is None: return
        ITEMS[idx]["fn"]()
