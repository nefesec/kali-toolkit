"""Crack & hash — 4 outils."""

from core import ui, runner


def hashcat_run():
    ui.header("hashcat — dictionnaire")
    if not runner.check_tools(["hashcat"]): ui.pause(); return
    mode = ui.ask("mode (-m, ex: 0=MD5, 100=SHA1, 1000=NTLM, 22000=WPA)", default="0")
    hf   = ui.ask("fichier de hashes")
    wl   = ui.ask("wordlist", default="/usr/share/wordlists/rockyou.txt")
    if not hf: ui.pause(); return
    runner.run(["hashcat", "-m", mode, hf, wl], tag=f"hashcat-{mode}"); ui.pause()


def john_run():
    ui.header("John the Ripper")
    if not runner.check_tools(["john"]): ui.pause(); return
    hf = ui.ask("fichier de hashes"); wl = ui.ask("wordlist (vide=default)", default="")
    if not hf: ui.pause(); return
    args = ["john"]
    if wl: args += [f"--wordlist={wl}"]
    args.append(hf)
    runner.run(args, tag="john"); ui.pause()


def crunch_gen():
    ui.header("crunch — wordlist")
    if not runner.check_tools(["crunch"]): ui.pause(); return
    mn  = ui.ask("min len", default="8"); mx = ui.ask("max len", default="8")
    chs = ui.ask("charset", default="abcdefghijklmnopqrstuvwxyz0123456789")
    out = ui.ask("fichier sortie", default="wl.txt")
    runner.run(["crunch", mn, mx, chs, "-o", out], tag="crunch"); ui.pause()


def hash_identify():
    ui.header("hash-identifier")
    if not runner.check_tools(["hash-identifier"]): ui.pause(); return
    runner.run(["hash-identifier"], tag="hash-id"); ui.pause()


ITEMS = [
    {
        "label": "hashcat — dictionnaire", "fn": hashcat_run, "status": "ok",
        "info": """Moteur de crack le plus rapide (GPU). Support 300+ types de hash.

MODES COURANTS :
  0    = MD5            (instantané)
  100  = SHA1           (très rapide)
  500  = MD5crypt       (Linux /etc/shadow ancien)
  1000 = NTLM           (Windows)
  1800 = SHA-512 crypt  (Linux /etc/shadow moderne)
  3200 = bcrypt         (lent par design, hash sécurisé)
  22000= WPA-PMKID+EAPOL (WiFi)

PERFS (RTX 3060) :
  MD5    ~ 5 GH/s        → rockyou en <1s
  NTLM   ~ 30 GH/s       → rockyou en <1s
  bcrypt ~ 5 kH/s        → rockyou en 1 mois (intentionnel)
  WPA    ~ 500 kH/s      → rockyou en 30s

TIPS        : -a 3 = bruteforce avec mask (?l?d?d?d?d?l?l = lower+4digit+2lower)
              -r rules/best64.rule pour ajouter mutations à la wordlist
LIMITES     : sans GPU dédié = CPU = 100-1000× plus lent"""
    },
    {
        "label": "John the Ripper", "fn": john_run, "status": "ok",
        "info": """Alternative historique à hashcat, CPU-only, excellent pour :
- hashes Unix classiques (DES, MD5crypt)
- Détection auto du type de hash
- Mode 'single' (utilise infos GECOS de /etc/passwd)

QUAND       : si pas de GPU, ou hash exotique non supporté hashcat
TIPS        : 'unshadow /etc/passwd /etc/shadow > h.txt' pour combiner
              'john --show h.txt' pour voir résultats déjà crackés"""
    },
    {
        "label": "crunch — gen wordlist", "fn": crunch_gen, "status": "tool",
        "info": """Génère toutes les combinaisons possibles d'un charset entre min et max longueur.

EXEMPLES    :
  crunch 8 8 0123456789ABCDEF -o hex.txt    → tous PIN 8 hex MAJ (4.3 milliards)
  crunch 4 6 -o num.txt                     → 0000-999999 alphanum
  crunch 8 8 -t @@@@%%%%                    → 4 lettres + 4 chiffres
ATTENTION   : taille du fichier explose vite
              8 alphanum mixte = 218 To
              → pipe direct vers aircrack/hashcat au lieu de -o fichier"""
    },
    {
        "label": "hash-identifier", "fn": hash_identify, "status": "tool",
        "info": """Devine le type d'un hash inconnu (interactif).

QUAND       : tu trouves un hash en pillage et tu ne sais pas son format
ENTRÉE      : colle le hash, lis les suggestions classées par probabilité
TIPS        : compléter avec 'hashid' (autre outil similaire, parfois plus précis)
              Pour vérifier : longueur typique
                MD5    = 32 hex
                SHA1   = 40 hex
                SHA256 = 64 hex
                bcrypt = commence par $2a$ / $2b$ / $2y$
                NTLM   = 32 hex (mais utiliser hashcat -m 1000)"""
    },
]


def menu():
    while True:
        idx = ui.menu("CRACK & HASH", ITEMS)
        if idx is None: return
        ITEMS[idx]["fn"]()
