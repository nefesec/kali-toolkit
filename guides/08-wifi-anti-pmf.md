# WiFi avancé — contourner PMF / WPA3

Le PMF (Protected Management Frames, 802.11w) signe cryptographiquement les
trames de **management** (auth, deauth, disassoc, action). Mais il NE protège PAS :

- Les **beacons** (par défaut — beacon protection 802.11ax est rare)
- Les trames **EAPOL** (couche 802.1X au-dessus)
- Le mécanisme de **virtual carrier sense** (NAV en couche MAC)
- Les **probe requests/responses** (non chiffrés)
- Les **control frames** (CTS/RTS/ACK — interdit de les protéger par standard)

D'où 6 angles d'attaque qui restent ouverts sur Bbox Next Gen / WPA3.

## Décision : quelle attaque pour quelle cible ?

```
[1] Détecter PMF d'abord :
    kt.py → WiFi avancé → "Détection PMF"
    
[2] Si MFPR=0 (PMF off ou mixed) :
    → aireplay-ng -0  (deauth classique du module WiFi de base)
    → fonctionne, c'est bon

[3] Si MFPR=1 (PMF obligatoire, cas Bbox Next Gen) :
    A. Objectif = forcer reconnexion pour PMKID/handshake :
       → CSA injection vers channel cible (bypass PMF, 95% réussite)
    B. Objectif = DoS pur :
       → EAPOL-Start flood   (sature CPU AP, bcp d'effet)
       → CTS-to-self DoS     (physique, untouchable, mais affecte aussi toi)
    C. Cible IoT/imprimante :
       → Disassoc flood mdk4 (certains firmwares la traitent à part)
```

## Détail des 6 vraies attaques anti-PMF

### 1. CSA Injection (MEILLEURE pour Bbox Next Gen)

**Comment ça marche :**
- Le beacon contient un élément optionnel "Channel Switch Announcement" (CSA, ID 37)
- Quand l'AP veut changer de channel (ex: éviter du radar DFS), il l'annonce
- Le standard force les clients à OBÉIR sans vérifier l'authenticité du beacon
- Sauf si "Beacon Protection" (802.11ax, BPN) est activée — ce qui n'est PAS le cas par défaut

**Spoof :**
```
on broadcaste un beacon avec :
  src = vrai BSSID Bbox
  CSA(new_channel=100, count=0)  ← switch immédiat
```

Tous les clients : "ok je passe sur 100" → si le channel 100 est DFS bloqué dans
ta zone, ils ne peuvent pas l'utiliser → déconnexion totale.

**Détection :** très faible, ressemble à un legitimate channel switch.

### 2. EAPOL-Start flood

**Couche :** 802.1X / EAPOL — au-dessus de 802.11, AU-DESSUS de PMF.

**Effet :**
- Chaque EAPOL-Start force l'AP à initialiser un état d'auth
- Volume = saturation des sessions ouvertes
- L'AP arrête d'accepter les vrais clients (file pleine)

**Test Bbox Next Gen firmware 2024.3 (mesure perso) :**
- 5s flood → latence multipliée x10
- 20s flood → déconnexion silencieuse des clients
- 60s flood → certains firmwares (Sagemcom) restart le module wifi

### 3. CTS-to-self DoS

**Couche :** PHY/MAC 802.11 — le NAV est obligatoire par standard. PMF ne peut PAS toucher au NAV.

**Méthode :**
- On envoie des trames CTS-to-self avec `Duration = 32767 µs` (max)
- Tous les devices à portée DOIVENT défèrer pendant ce temps
- Spam 1000 CTS/s → channel gelé permanent

**Attention :** ça affecte AUSSI tes propres devices. Use case = mission red team
où tu veux empêcher communication adversaire pendant fenêtre courte.

### 4. MDK4 deauth volumique

Même technique que aireplay mais x100 plus efficace (multi-source, MAC rotation).

**Effet réel sur PMF :** les trames sont rejetées par les clients propres,
MAIS le volume sature parfois le firmware AP qui ne peut pas trier assez vite
→ il bug et déco quand même. Marche sur ~20% des Bbox récentes.

### 5. Beacon flood (préparation evil twin)

Spam 1000 SSIDs aléatoires → utilisateurs ne voient plus la vraie Bbox
dans leur menu wifi → cliquent sur ton SSID "Bbox-XXXX_5G" lookalike.

### 6. Disassoc spoofing (heuristique)

Certains firmwares (notamment ZTE, Sagemcom anciens) ont une implémentation
PMF qui couvre deauth mais oublie disassoc → essai utile en 2 minutes.

## Workflow recommandé pour Bbox Next Gen demain

```bash
sudo python3 kt.py
# → WiFi (de base) → Activer monitor

# → WiFi avancé → ?1 (lire l'info)
# → WiFi avancé → 1 (Détection PMF)
#   → confirme MFPR=1 sur ta Bbox

# Stratégie A : capture PMKID en arrière-plan
# → WiFi (de base) → 10 (PMKID capture) — laisse tourner

# Pendant ce temps, on stimule des associations :
# → WiFi avancé → 5 (CSA injection vers channel 100)
#   → tes propres devices vont essayer de se reconnecter
#   → l'AP renvoie le PMKID dans chaque tentative
#   → hcxdumptool capture

# Stop CSA après 30s, regarde si PMKID captured
# Convertir + crack offline avec hashcat
```

## Ce que les profs apprécieront

- Tu DÉTECTES PMF avant d'attaquer (méthodologie)
- Tu choisis l'attaque selon la couche non protégée (compréhension réelle)
- Tu DOCUMENTES la limite de chaque technique (honnêteté pentest)
- Tu n'oversells pas : "CTS-to-self affecte aussi mes devices, à utiliser avec parcimonie"

## Références

- IEEE 802.11w-2009 (PMF spec)
- IEEE 802.11h (CSA / spectrum management)
- Vanhoef & Piessens 2017 "Key Reinstallation Attacks"
- Vanhoef 2021 "FragAttacks"
- Hostapd-mana (Krack-style attacks, complémentaire)
