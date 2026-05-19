"""Affichage des guides markdown."""

import os
from core import ui

GUIDE_DIR = os.path.join(os.path.dirname(__file__), "..", "guides")


def _list_guides():
    if not os.path.isdir(GUIDE_DIR):
        return []
    return sorted(f for f in os.listdir(GUIDE_DIR) if f.endswith(".md"))


def _show(filename):
    path = os.path.join(GUIDE_DIR, filename)
    try:
        with open(path) as f:
            content = f.read()
        ui.clear()
        # rendu markdown minimal (ANSI)
        for line in content.splitlines():
            if line.startswith("# "):
                print(f"{ui.C}{ui.BOLD}{line[2:]}{ui.RESET}\n")
            elif line.startswith("## "):
                print(f"\n{ui.Y}{ui.BOLD}{line[3:]}{ui.RESET}")
            elif line.startswith("### "):
                print(f"\n{ui.M}{line[4:]}{ui.RESET}")
            elif line.startswith("```"):
                print(f"{ui.D}{line}{ui.RESET}")
            elif line.startswith("- "):
                print(f"  {ui.C}•{ui.RESET} {line[2:]}")
            else:
                print(line)
        ui.pause()
    except FileNotFoundError:
        ui.err(f"guide introuvable : {filename}")
        ui.pause()


def menu():
    while True:
        guides = _list_guides()
        if not guides:
            ui.err("aucun guide trouvé dans /guides")
            ui.pause()
            return
        items = [(g.replace(".md", "").replace("-", " "), (lambda g=g: _show(g))) for g in guides]
        idx = ui.menu("GUIDES", items)
        if idx is None: return
        items[idx][1]()
