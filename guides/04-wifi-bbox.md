# Spécifique Bbox (Bouygues Telecom)

## Reconnaissance d'une Bbox

- SSID par défaut : `Bbox-XXXXXX` (6 hex) ou `BBOX-XXXXXX`
- BSSID OUI Bouygues / Sagemcom / Technicolor (fournisseurs box) — observer le préfixe MAC
- Encryption : WPA2-PSK (vieilles) / WPA2/WPA3 mixed (Next Gen)

## Bbox Next Gen — particularités

- WiFi 6 (ax) sur 2.4 + 5 GHz → carte AX recommandée
- WPA2/WPA3 transition → certaines attaques classiques cassent, le PMKID reste possible sur le SSID WPA2
- WPS souvent désactivé par défaut sur les firmwares récents — à vérifier
- Bandes 5 GHz : channels 36-48 et 100-140 (DFS)
- Protection PMF (Protected Management Frames) activée → **deauth classique bloqué**

## Si PMF est activé (cas Next Gen)

L'attaque deauth `aireplay-ng -0` est **ignorée** par les clients WPA3/PMF.
Alternatives :

1. **PMKID** (ne nécessite aucune deauth) :
   ```bash
   sudo hcxdumptool -i wlan0mon -w bbox.pcapng --enable_status=1
   # attendre 1-2 min ou jusqu'à voir "PMKID" dans les logs
   sudo hcxpcapngtool -o bbox.hc22000 bbox.pcapng
   hashcat -m 22000 bbox.hc22000 wordlist.txt
   ```

2. **Beacon flood / Channel switch announce** (oblige le client à changer de canal)

3. **Evil twin + portail captif** : monter une fausse Bbox-XXXX, attendre que l'utilisateur retape son mdp

## Wordlist adaptée Bbox

Les Bbox utilisent historiquement des mdp par défaut de **8 caractères** mixant :
- Anciennes box : 8 hex MAJ (ex: `A3F2D9C1`)
- Bbox 2 / Miami : 10 caractères alphanumériques
- Bbox Next Gen : 10 caractères mélange a-zA-Z0-9

### Génération wordlist 8 hex (anciennes)

```bash
crunch 8 8 0123456789ABCDEF -o bbox-old.txt
# 16^8 = 4.3 milliards = ~6h avec un GPU correct sur hashcat
```

### Génération wordlist 10 alphanum (récentes)

Le full bruteforce est inhumain (62^10 = 8.4*10^17).
→ utiliser :
- Wordlists ciblées (cf. github : `bouygues-bbox-wordlist`, dérivés de SSID)
- Masques hashcat partiels si tu as un indice (ex: `?u?l?l?d?d?d?d?d?l?l`)

## Conseil pour ton test demain

- Si WPS est activé sur ta Bbox Next Gen → essaie pixie dust **en premier** (gain de temps)
- Sinon PMKID + petite wordlist ciblée
- Backup : evil twin avec portail captif (la box demande qu'on retape le code WiFi imprimé dessous)

## Vérifs avant test

```bash
# voir si la box répond aux deauth (PMF désactivé)
sudo aireplay-ng -0 1 -a <BSSID_BBOX> wlan0mon
# si "got disconnected" sur ton tel  → PMF off → deauth utilisable
# sinon → PMF on → bascule sur PMKID/evil twin
```
