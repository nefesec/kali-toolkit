"""UI helpers : couleurs ANSI, bannières, menus avec info."""

import os

R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
M = "\033[95m"
C = "\033[96m"
W = "\033[97m"
D = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = f"""{C}{BOLD}
   ██╗  ██╗████████╗
   ██║ ██╔╝╚══██╔══╝   Kali Toolkit
   █████╔╝    ██║      v1.0
   ██╔═██╗    ██║      {Y}~ pentest all-in-one ~{C}
   ██║  ██╗   ██║
   ╚═╝  ╚═╝   ╚═╝
{RESET}"""

# Tags de fiabilité face aux équipements modernes
STATUS = {
    "ok":      f"{G}[ OK   ]{RESET}",      # fonctionne globalement
    "cfg":     f"{Y}[ CFG  ]{RESET}",      # dépend de la config cible
    "old":     f"{R}[ VIEUX]{RESET}",      # souvent obsolète sur firmware récent
    "tool":    f"{C}[ TOOL ]{RESET}",      # outil utilitaire (pas une attaque)
}


def clear():
    os.system("clear" if os.name == "posix" else "cls")


def banner():
    clear()
    print(BANNER)


def info(msg):  print(f"{C}[*]{RESET} {msg}")
def ok(msg):    print(f"{G}[+]{RESET} {msg}")
def warn(msg):  print(f"{Y}[!]{RESET} {msg}")
def err(msg):   print(f"{R}[-]{RESET} {msg}")


def header(title):
    line = "─" * (len(title) + 4)
    print(f"\n{B}{line}{RESET}")
    print(f"{B}│ {BOLD}{title}{RESET}{B} │{RESET}")
    print(f"{B}{line}{RESET}\n")


def ask(prompt, default=None):
    suffix = f" {D}[{default}]{RESET}" if default else ""
    val = input(f"{Y}?{RESET} {prompt}{suffix}: ").strip()
    return val if val else (default or "")


def confirm(prompt):
    val = input(f"{Y}?{RESET} {prompt} [o/N]: ").strip().lower()
    return val in ("o", "y", "oui", "yes")


def _show_info(item):
    """Affiche le bloc d'info d'une attaque."""
    clear()
    print(f"\n{C}{BOLD}{item['label']}{RESET}  {STATUS.get(item.get('status','ok'), '')}\n")
    print(f"{D}{'─' * 60}{RESET}")
    print(item.get("info", "(pas d'info disponible)").strip())
    print(f"{D}{'─' * 60}{RESET}\n")
    pause()


def menu(title, items):
    """
    items: list de dicts {label, fn, status?, info?} OU list de tuples (label, fn) (compat).
    Tape un nombre pour lancer, '?N' pour voir l'info de l'item N, 0 pour retour.
    """
    # Normalise tuples → dicts
    norm = []
    for it in items:
        if isinstance(it, tuple):
            norm.append({"label": it[0], "fn": it[1], "status": "ok", "info": ""})
        else:
            norm.append(it)

    while True:
        header(title)
        for i, it in enumerate(norm, 1):
            tag = STATUS.get(it.get("status", "ok"), STATUS["ok"])
            print(f"  {C}{i:>2}{RESET}. {tag}  {it['label']}")
        print(f"  {D} 0{RESET}. {D}retour{RESET}")
        print(f"\n  {D}tape un numéro pour lancer · '?N' pour explications de l'item N{RESET}\n")

        try:
            choice = input(f"{Y}>{RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return None
        if not choice:
            continue

        # ?N → afficher info
        if choice.startswith("?"):
            try:
                n = int(choice[1:].strip())
                if 1 <= n <= len(norm):
                    _show_info(norm[n-1])
                    continue
            except ValueError:
                pass
            warn("usage : ?N  (ex: ?3)")
            continue

        # Nombre → lancer
        try:
            n = int(choice)
            if n == 0: return None
            if 1 <= n <= len(norm):
                return n - 1
            warn("choix invalide")
        except ValueError:
            warn("entrée invalide")


def pause():
    try:
        input(f"\n{D}[entrée pour continuer]{RESET}")
    except (KeyboardInterrupt, EOFError):
        print()


def pause_with_analysis():
    """Comme pause() mais propose d'analyser le dernier log (loot extraction)."""
    print()
    if confirm("Analyser automatiquement ce qui a été capturé ?"):
        from modules.analyzer import analyze_latest
        analyze_latest()
    else:
        pause()
