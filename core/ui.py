"""UI helpers : couleurs ANSI, bannières, menus."""

import os
import sys

# Couleurs ANSI
R = "\033[91m"   # rouge
G = "\033[92m"   # vert
Y = "\033[93m"   # jaune
B = "\033[94m"   # bleu
M = "\033[95m"   # magenta
C = "\033[96m"   # cyan
W = "\033[97m"   # blanc
D = "\033[2m"    # dim
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


def clear():
    os.system("clear" if os.name == "posix" else "cls")


def banner():
    clear()
    print(BANNER)


def info(msg):
    print(f"{C}[*]{RESET} {msg}")


def ok(msg):
    print(f"{G}[+]{RESET} {msg}")


def warn(msg):
    print(f"{Y}[!]{RESET} {msg}")


def err(msg):
    print(f"{R}[-]{RESET} {msg}")


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


def menu(title, items):
    """items: list of (label, callable). Renvoie l'index choisi ou None."""
    header(title)
    for i, (label, _) in enumerate(items, 1):
        print(f"  {C}{i:>2}{RESET}. {label}")
    print(f"  {D} 0{RESET}. {D}retour{RESET}")
    print()
    while True:
        try:
            choice = input(f"{Y}>{RESET} ").strip()
            if not choice:
                continue
            n = int(choice)
            if n == 0:
                return None
            if 1 <= n <= len(items):
                return n - 1
            warn("choix invalide")
        except ValueError:
            warn("entrée invalide")
        except (KeyboardInterrupt, EOFError):
            print()
            return None


def pause():
    input(f"\n{D}[entrée pour continuer]{RESET}")
