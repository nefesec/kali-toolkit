# Reconnaissance

## Ordre recommandé

1. **WHOIS** — propriétaire, registrar, NS, dates
2. **dnsrecon** — sous-domaines, MX, TXT, transfert de zone
3. **theHarvester** — emails (utiles pour phishing/password spray)
4. **WhatWeb** — stack technique du site (CMS, framework, JS libs)
5. **Nmap quick** — ports ouverts top 100
6. **Nmap full** — tous ports + versions + OS
7. **Nmap vuln** — scripts NSE catégorie vuln

## Tips Nmap

- `-Pn` : skip ping (cible derrière FW qui drop ICMP)
- `-T0..T5` : timing — T4 par défaut, T2 si discret, T0 si IDS agressif
- `-sV --version-intensity 9` : pousse la détection de version
- `-oA basename` : sauve en 3 formats (XML/grepable/normal)

## Exemples utiles hors menu

```bash
# scan UDP des top 50 (souvent oublié)
nmap -sU --top-ports 50 cible

# détection précise avec OS fingerprint
nmap -sV -O --osscan-guess cible
```

## OSINT léger sans installer rien

- `crt.sh` (web) → sous-domaines via certificats SSL
- `wayback machine` → versions anciennes du site
- DNS dumpster, Shodan, censys → infra publique
