#!/bin/bash
# Installe les outils nécessaires (Kali Linux)

set -e

if ! command -v apt >/dev/null; then
  echo "[-] apt introuvable — distribution non supportée (Kali/Debian/Ubuntu uniquement)"
  exit 1
fi

PKGS=(
  # recon
  nmap whois dnsrecon theharvester whatweb
  # wifi
  aircrack-ng reaver bully hcxdumptool hcxtools
  # network
  arp-scan dsniff ettercap-text-only sslstrip tcpdump nbtscan
  # web
  dirb gobuster nikto sqlmap wpscan
  # exploit
  exploitdb metasploit-framework hydra
  # crack
  hashcat john crunch hash-identifier
  # divers
  iw wireless-tools macchanger
)

echo "[*] Installation des paquets nécessaires..."
sudo apt update
sudo apt install -y "${PKGS[@]}" || {
  echo "[!] Certains paquets n'ont pas pu être installés — continue quand même"
}

# Décompresser rockyou si présent
if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
  echo "[*] Décompression rockyou.txt..."
  sudo gunzip /usr/share/wordlists/rockyou.txt.gz
fi

echo ""
echo "[+] Installation terminée."
echo "[+] Lance : sudo python3 kt.py"
