# Kali Toolkit

**Outil all-in-one CLI pour pentest pédagogique** — 50 actions + 8 guides
sous une interface menu unique. Chaque attaque a une **fiche détaillée**
accessible via `?N` dans le menu (description, prérequis, sortie, tips, limites).

Inclut un module **WiFi avancé anti-PMF / WPA3** (CSA injection, EAPOL flood,
CTS-to-self DoS) pour contourner les protections des box modernes type Bbox Next Gen.

> Usage uniquement sur des cibles **dont tu as l'autorisation explicite**.

## Statut honnête des attaques (face aux équipements modernes)

Chaque item du menu affiche un tag :

- `[ OK   ]` — fonctionne globalement
- `[ CFG  ]` — dépend de la config cible
- `[ VIEUX]` — souvent obsolète sur firmware/OS récent
- `[ TOOL ]` — outil utilitaire (pas une attaque)

Voir `guides/07-limites-equipements-modernes.md` pour le détail par scénario
(Bbox Next Gen, WPA3, EDR Windows, WAF, etc.).

## Catégories

| Module          | Outils                                                                                |
|-----------------|----------------------------------------------------------------------------------------|
| Reconnaissance  | nmap (4 modes), whois, dnsrecon, theHarvester, whatweb                                 |
| WiFi (12)       | airmon/airodump/aireplay, reaver, bully, hcxdumptool, aircrack, hashcat               |
| **WiFi avancé (8)** | **CSA injection, CTS-to-self DoS, EAPOL flood, MDK4 (5 modes), détecteur PMF** |
| Réseau LAN (8)  | arp-scan, arpspoof, dnsspoof, ettercap, sslstrip, tcpdump, nbtscan, port-knock         |
| Web (6)         | dirb, gobuster, nikto, sqlmap, wpscan, xsstrike                                        |
| Exploitation (4)| searchsploit, msfconsole, hydra (SSH + FTP)                                            |
| Crack & Hash (4)| hashcat, john, crunch, hash-identifier                                                 |
| Guides          | méthodo · recon · WiFi (bases + Bbox) · web · reporting · **limites équipements**     |

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

## Utilisation du menu

```
1, 2, 3 ...    → lance l'attaque
?N             → affiche fiche détaillée de l'attaque N
0              → retour menu précédent
Ctrl-C         → interrompt l'attaque en cours, retour menu
```

## Logs

Tous les outputs sont sauvegardés dans `~/.kt-logs/` avec timestamp, prêts pour le rapport.

## Structure

```
kali-toolkit/
├── kt.py                # entrée principale
├── core/
│   ├── ui.py            # menu + info ?N + tags statut
│   └── runner.py        # wrapper subprocess + logs
├── modules/
│   ├── recon.py         # 8 + fiches info
│   ├── wifi.py          # 12 + fiches info
│   ├── network.py       # 8 + fiches info
│   ├── web.py           # 6 + fiches info
│   ├── exploit.py       # 4 + fiches info
│   ├── crack.py         # 4 + fiches info
│   └── guides.py        # rendu markdown des guides
├── guides/              # 7 cheat sheets
└── install.sh
```

## Limites connues (à dire au prof avant qu'il pose la question)

Ce toolkit reste un wrapper pédagogique. **Ce qu'il ne fait PAS** :

- Pas d'évasion EDR moderne (Defender ATP, CrowdStrike, SentinelOne)
- Pas de bypass WAF avancé (Cloudflare, Akamai, Imperva sortent les tools de la boîte)
- Pas de cracking WPA3 (SAE protège contre le PMKID/handshake)
- Pas de social engineering (phishing kits, evil twin avec portail captif sont à part)
- Pas de C2 (Cobalt Strike, Sliver, Mythic = environnement op pro)
- Pas de Bluetooth / SDR / hardware hacking

Pour ces sujets : monter des labs dédiés ou suivre des certifs (OSCP, PNPT, CRTP).

## Conformité légale

L'utilisation contre un système sans autorisation **écrite** du propriétaire
constitue une intrusion (Art. 323-1 du Code pénal français, équivalents UE/US).

Usage légitime :
- Ton propre matériel
- Cyber-ranges (HackTheBox, TryHackMe, OffSec labs, PortSwigger Web Academy)
- Missions pentest sous contrat
- Examen scolaire en environnement contrôlé

## Licence

MIT — voir `LICENSE`.
