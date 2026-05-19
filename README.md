# Kali Toolkit

**Outil all-in-one CLI pour pentest** — réunit 42 actions et 6 guides méthodologiques
dans une interface menu unique pour Kali Linux.

> Projet pédagogique. Usage uniquement sur des cibles **dont tu as l'autorisation explicite**.

## Catégories

| Module          | Outils inclus                                                                                  |
|-----------------|------------------------------------------------------------------------------------------------|
| Reconnaissance  | nmap (4 modes), whois, dnsrecon, theHarvester, whatweb                                          |
| WiFi (12)       | airmon/airodump/aireplay, reaver, bully, hcxdumptool, aircrack, hashcat (mode 22000)            |
| Réseau LAN (8)  | arp-scan, arpspoof, dnsspoof, ettercap, sslstrip, tcpdump, nbtscan, port-knock                  |
| Web (6)         | dirb, gobuster, nikto, sqlmap, wpscan, xsstrike                                                 |
| Exploitation (4)| searchsploit, msfconsole, hydra (SSH + FTP)                                                     |
| Crack & Hash (4)| hashcat, john, crunch, hash-identifier                                                          |
| Guides          | méthodologie, recon, WiFi (bases + spécifique Bbox), web, reporting                             |

## Installation

```bash
git clone https://github.com/nefesec/kali-toolkit.git
cd kali-toolkit
chmod +x install.sh
./install.sh
```

## Lancement

```bash
sudo python3 kt.py
```

## Logs

Tous les outputs sont sauvegardés dans `~/.kt-logs/` avec timestamp, prêts pour le rapport.

## Structure

```
kali-toolkit/
├── kt.py                # entrée principale (menu)
├── core/
│   ├── ui.py            # couleurs, menus
│   └── runner.py        # wrapper subprocess + logs
├── modules/
│   ├── recon.py         # 8 outils
│   ├── wifi.py          # 12 outils
│   ├── network.py       # 8 outils
│   ├── web.py           # 6 outils
│   ├── exploit.py       # 4 outils
│   ├── crack.py         # 4 outils
│   └── guides.py        # rendu markdown
├── guides/              # méthodologie + cheat sheets
└── install.sh
```

## Conformité légale

L'utilisation de ces outils contre un système sans autorisation **écrite** du propriétaire
constitue une intrusion (Art. 323-1 du Code pénal en France). Ce projet est destiné à :

- Tests sur ton propre matériel
- Cyber-ranges (HackTheBox, TryHackMe, OffSec labs)
- Missions de pentest sous contrat
- Apprentissage en environnement isolé (VM)

## Licence

MIT — voir `LICENSE`.
