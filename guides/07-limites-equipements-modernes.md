# Limites face aux équipements modernes

Tableau honnête de ce qui fonctionne ou non en 2026 sur du matériel récent.

## Légende statut

- **OK**     : fonctionne globalement
- **CFG**    : dépend de la config cible (à tester avant)
- **VIEUX**  : souvent obsolète sur firmware récent
- **TOOL**   : outil utilitaire, pas une attaque en soi

## WiFi — récap par attaque

| Attaque              | Box ancienne (2015-) | Box récente (2020+)         | WPA3 / Next Gen       |
|----------------------|----------------------|-----------------------------|------------------------|
| Deauth client/all    | OK                   | CFG (PMF souvent on)        | KO (PMF obligatoire)   |
| Handshake capture    | OK                   | CFG (sans deauth = long)    | KO (clé éphémère SAE)  |
| WPS pixie dust       | OK si WPS on         | KO (WPS off par défaut)     | KO                     |
| WPS bully bruteforce | OK si WPS on         | KO (idem)                   | KO                     |
| PMKID capture        | OK                   | OK (WPA2) / KO (WPA3 pur)   | KO sur SSID WPA3 seul  |
| Crack PSK fort       | KO (mdp random)      | KO                          | KO                     |
| Evil twin + portail  | OK                   | OK (social engineering)     | OK                     |

## Cas Bbox Next Gen (2024+) — ce que dit le terrain

- PMF activé d'usine → deauth bloqué
- WPS désactivé d'usine → reaver/bully inutiles
- WPA2/WPA3 mode transition → SSID visible en WPA2 (PMKID possible)
- Mot de passe d'usine : 10 caractères alphanum mixte aléatoires (62^10 = uncrackable bruteforce)
- DHCP snooping + protection broadcast côté LAN

### Stratégies viables sur Bbox Next Gen

1. **PMKID + wordlist ciblée** : si mdp non modifié, faible chance avec wordlist random,
   mais si l'utilisateur a personnalisé en utilisant un mot du dico → crackable
2. **Evil twin portail captif** (ingénierie sociale) : monter un SSID Bbox-XXXX identique,
   présenter un faux portail "Mise à jour requise, retapez le mdp WiFi". Très efficace.
3. **Côté LAN si accès filaire** : la box reste vulnérable aux scans LAN classiques,
   admin panel souvent en HTTP local

## Réseau LAN — récap

| Attaque       | Switch domestique | Switch entreprise (DAI) | Cisco/Aruba pro |
|---------------|-------------------|--------------------------|------------------|
| ARP scan      | OK                | OK                       | OK               |
| ARP spoof     | OK                | KO (DAI bloque)          | KO               |
| DNS spoof     | OK si client UDP  | KO si DoH/DoT activé    | KO               |
| SSLstrip      | KO (HSTS partout) | KO                       | KO               |
| NetBIOS scan  | KO (Win10+ off)   | CFG                      | CFG              |

## Web — récap

| Attaque             | Site perso / WordPress | Site avec WAF (CF/Akamai) | Bug bounty pro |
|---------------------|-------------------------|----------------------------|------------------|
| dirb/gobuster       | OK                      | CFG (rate-limit)           | OK avec proxy   |
| nikto               | OK                      | KO (signature en 1s)       | KO              |
| sqlmap              | OK                      | CFG (tampers nécessaires)  | CFG             |
| WPScan              | OK                      | CFG (rate-limit)           | OK              |
| XSStrike            | OK                      | KO sur fichiers minimes    | CFG             |

## OS Windows moderne — récap

| Attaque                 | Win 10/11 + Defender | Win serveur + EDR |
|-------------------------|-----------------------|--------------------|
| msf classique           | KO (signatures)       | KO                 |
| meterpreter natif       | KO                    | KO                 |
| msfvenom payload obfus. | CFG                   | KO                 |
| Mimikatz                | KO (Defender ATP)     | KO                 |
| Pour vrais tests        | Cobalt Strike / OST   | Idem               |

## Conclusion honnête

Ce toolkit est **pédagogique** : il enseigne les bases et reste très efficace en
CTF / labs / vieux matériel / config faible. Pour du pentest réel face à du matériel
moderne bien configuré, beaucoup d'attaques nécessitent :

- Évasion EDR (payloads custom, AMSI bypass, etc.)
- Bypass WAF (tampers, polymorphism)
- Ingénierie sociale (le facteur humain reste le maillon faible n°1)
- Outils commerciaux (Cobalt Strike, Burp Pro, NetSPI tools)
- Connaissance profonde de la cible (offline recon, codecs/protocoles propriétaires)

**Ne pas oublier** : le but d'un pentest c'est de **trouver** des vulnérabilités,
pas de **démontrer** des attaques. Un rapport qui dit "rien trouvé après 5 jours
sur cible moderne" peut être un excellent rapport.
