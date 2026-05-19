"""Reconnaissance : 8 attaques / scans."""

from core import ui, runner


def nmap_quick():
    ui.header("Nmap — scan rapide (top 100 ports)")
    target = ui.ask("cible (IP ou domaine)")
    if not target: return
    runner.run(["nmap", "-F", "-T4", target], tag="nmap-quick")
    ui.pause()


def nmap_full():
    ui.header("Nmap — scan complet + détection services/OS")
    if not runner.check_tools(["nmap"]): ui.pause(); return
    target = ui.ask("cible")
    if not target: return
    runner.run(["nmap", "-sS", "-sV", "-O", "-p-", "-T4", target], tag="nmap-full", root=True)
    ui.pause()


def nmap_vuln():
    ui.header("Nmap — scripts de vulnérabilités")
    target = ui.ask("cible")
    if not target: return
    runner.run(["nmap", "--script", "vuln", "-sV", target], tag="nmap-vuln")
    ui.pause()


def nmap_stealth():
    ui.header("Nmap — scan furtif (SYN, slow)")
    target = ui.ask("cible")
    if not target: return
    runner.run(["nmap", "-sS", "-T2", "-f", "-D", "RND:5", target], tag="nmap-stealth", root=True)
    ui.pause()


def whois_lookup():
    ui.header("WHOIS — info domaine")
    if not runner.check_tools(["whois"]): ui.pause(); return
    target = ui.ask("domaine")
    if not target: return
    runner.run(["whois", target], tag="whois")
    ui.pause()


def dnsrecon():
    ui.header("dnsrecon — énumération DNS")
    if not runner.check_tools(["dnsrecon"]): ui.pause(); return
    target = ui.ask("domaine")
    if not target: return
    runner.run(["dnsrecon", "-d", target, "-t", "std"], tag="dnsrecon")
    ui.pause()


def theharvester():
    ui.header("theHarvester — OSINT emails/sous-domaines")
    if not runner.check_tools(["theHarvester"]):
        ui.warn("essai avec 'theharvester' (minuscule)")
        if not runner.check_tools(["theharvester"]): ui.pause(); return
        binary = "theharvester"
    else:
        binary = "theHarvester"
    target = ui.ask("domaine")
    if not target: return
    runner.run([binary, "-d", target, "-b", "all", "-l", "200"], tag="harvester")
    ui.pause()


def whatweb():
    ui.header("WhatWeb — fingerprint tech web")
    if not runner.check_tools(["whatweb"]): ui.pause(); return
    target = ui.ask("URL (ex: https://example.com)")
    if not target: return
    runner.run(["whatweb", "-v", target], tag="whatweb")
    ui.pause()


ITEMS = [
    ("Nmap — scan rapide (top 100)",   nmap_quick),
    ("Nmap — scan complet + OS",       nmap_full),
    ("Nmap — scripts vulnérabilités",  nmap_vuln),
    ("Nmap — scan furtif",             nmap_stealth),
    ("WHOIS — info domaine",           whois_lookup),
    ("dnsrecon — énum DNS",            dnsrecon),
    ("theHarvester — OSINT emails",    theharvester),
    ("WhatWeb — fingerprint web",      whatweb),
]


def menu():
    while True:
        idx = ui.menu("RECONNAISSANCE", ITEMS)
        if idx is None: return
        ITEMS[idx][1]()
