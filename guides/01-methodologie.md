# Méthodologie pentest — vue d'ensemble

## 5 phases classiques

1. **Reconnaissance** — passive (OSINT) puis active (scan)
2. **Énumération** — services, versions, users, partages
3. **Exploitation** — vuln connues, mauvaises configs, credentials
4. **Post-exploitation** — persistence, escalade, pivot
5. **Reporting** — preuves, impact, remédiation

## Avant TOUT pentest

- Autorisation **écrite et signée** (scope clair, IPs/domaines listés)
- Fenêtre de tir (heures autorisées)
- Contact d'urgence côté client
- Ne JAMAIS sortir du périmètre défini

## Règles d'or

- Logger tout (le toolkit le fait dans `~/.kt-logs/`)
- Pas de destruction de données
- Pas de DoS sauf si explicitement autorisé
- Restaurer l'état initial après tests

## Workflow type avec ce toolkit

```
1. RECON           → nmap, whatweb, theharvester
2. WIFI / RÉSEAU   → cartographier l'environnement
3. WEB             → si appli expose des endpoints
4. EXPLOITATION    → searchsploit + msf sur vulns trouvées
5. CRACK           → si hashes récupérés
```
