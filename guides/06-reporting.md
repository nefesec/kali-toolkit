# Reporting

## Structure type d'un rapport pentest

1. **Résumé exécutif** (1 page, non-technique)
   - Contexte, périmètre, dates
   - Score global de risque
   - 3-5 findings critiques + recommandation principale

2. **Méthodologie**
   - Outils utilisés
   - Phases couvertes
   - Limites du test

3. **Findings détaillés** (par vuln)
   - Titre + sévérité (CVSS si possible)
   - Description
   - Preuve de concept (screenshot/commande)
   - Impact business
   - Remédiation

4. **Annexes**
   - Logs bruts (extraits)
   - Liste IPs/services scannés
   - Bibliographie / CVE référencées

## CVSS rapide

```
Critical : 9.0-10.0    (RCE auth bypass, full DB dump)
High     : 7.0-8.9     (SQLi sur table sensible, XSS stockée)
Medium   : 4.0-6.9     (XSS reflétée, info leak)
Low      : 0.1-3.9     (headers manquants, version disclosure)
```

## Logs du toolkit

Tous les outputs sont dans `~/.kt-logs/` avec timestamp.
À joindre comme preuves dans le rapport.

```bash
ls -lt ~/.kt-logs/ | head -20
```

## Templates utiles

- SANS Pentest Report Template
- OWASP Testing Guide structure
- PTES (Penetration Testing Execution Standard)

## Tips finaux

- Toujours **dater** les screenshots (overlay date dans gnome-screenshot)
- Hasher les .pcap (SHA256) pour intégrité
- Anonymiser les credentials trouvés dans le rapport public (`admin:****`)
