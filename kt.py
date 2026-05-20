#!/usr/bin/env python3
"""
Kali Toolkit — pentest all-in-one
Usage : sudo python3 kt.py
"""

import os
import sys

# permet d'importer core/ et modules/ depuis n'importe où
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import ui
from modules import (recon, wifi, wifi_wizard, wifi_adv, evil_twin, network,
                     web, exploit, crack, analyzer, beginner, guides)


MAIN = [
    ("MODE DÉBUTANT      (scénarios auto)",  beginner.menu),
    ("WiFi WIZARD        (airgeddon-style)", wifi_wizard.menu),
    ("Evil Twin / Fake AP (portail captif)", lambda: evil_twin.standalone()),
    ("Reconnaissance     (8 outils)",        recon.menu),
    ("WiFi              (12 outils)",        wifi.menu),
    ("WiFi avancé        (8 anti-PMF)",      wifi_adv.menu),
    ("Réseau LAN         (8 outils)",        network.menu),
    ("Web                (6 outils)",        web.menu),
    ("Exploitation       (4 outils)",        exploit.menu),
    ("Crack & Hash       (4 outils)",        crack.menu),
    ("Analyse post-attaque",                 analyzer.menu),
    ("Guides & méthodo",                     guides.menu),
]


def warn_if_not_root():
    if os.geteuid() != 0:
        ui.warn("pas root — certaines actions nécessitent sudo (auto-élevé via 'sudo' au besoin)")
        print()


def main():
    try:
        while True:
            ui.banner()
            warn_if_not_root()
            idx = ui.menu("MENU PRINCIPAL", MAIN)
            if idx is None:
                ui.info("bye")
                return
            try:
                MAIN[idx][1]()
            except KeyboardInterrupt:
                ui.warn("\ninterruption — retour menu")
    except (KeyboardInterrupt, EOFError):
        print()
        ui.info("bye")


if __name__ == "__main__":
    main()
