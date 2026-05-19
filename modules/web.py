"""Web : 6 actions — dirb, nikto, sqlmap, wpscan, xss, fuzz."""

from core import ui, runner


def dirb_scan():
    ui.header("Dirb — bruteforce répertoires")
    if not runner.check_tools(["dirb"]): ui.pause(); return
    url = ui.ask("URL (ex: http://target.com/)")
    wl  = ui.ask("wordlist", default="/usr/share/wordlists/dirb/common.txt")
    if not url: ui.pause(); return
    runner.run(["dirb", url, wl], tag="dirb")
    ui.pause()


def gobuster_scan():
    ui.header("Gobuster — bruteforce répertoires (rapide)")
    if not runner.check_tools(["gobuster"]): ui.pause(); return
    url = ui.ask("URL")
    wl  = ui.ask("wordlist", default="/usr/share/wordlists/dirb/common.txt")
    if not url: ui.pause(); return
    runner.run(["gobuster", "dir", "-u", url, "-w", wl, "-t", "50"], tag="gobuster")
    ui.pause()


def nikto_scan():
    ui.header("Nikto — scan vulnérabilités web")
    if not runner.check_tools(["nikto"]): ui.pause(); return
    url = ui.ask("URL")
    if not url: ui.pause(); return
    runner.run(["nikto", "-h", url], tag="nikto")
    ui.pause()


def sqlmap_scan():
    ui.header("sqlmap — test injection SQL")
    if not runner.check_tools(["sqlmap"]): ui.pause(); return
    url = ui.ask("URL avec paramètre (ex: http://x/p?id=1)")
    if not url: ui.pause(); return
    runner.run(["sqlmap", "-u", url, "--batch", "--level=2"], tag="sqlmap")
    ui.pause()


def wpscan_scan():
    ui.header("WPScan — audit WordPress")
    if not runner.check_tools(["wpscan"]): ui.pause(); return
    url = ui.ask("URL WordPress")
    if not url: ui.pause(); return
    runner.run(
        ["wpscan", "--url", url, "--enumerate", "vp,vt,u", "--random-user-agent"],
        tag="wpscan"
    )
    ui.pause()


def xss_test():
    ui.header("XSStrike — test XSS")
    if not runner.check_tools(["xsstrike"]):
        ui.warn("xsstrike absent — install : sudo apt install xsstrike")
        ui.pause(); return
    url = ui.ask("URL avec paramètre")
    if not url: ui.pause(); return
    runner.run(["xsstrike", "-u", url], tag="xsstrike")
    ui.pause()


ITEMS = [
    ("Dirb — bruteforce dirs",      dirb_scan),
    ("Gobuster — bruteforce dirs",  gobuster_scan),
    ("Nikto — vuln scan",           nikto_scan),
    ("sqlmap — SQL injection",      sqlmap_scan),
    ("WPScan — audit WordPress",    wpscan_scan),
    ("XSStrike — test XSS",         xss_test),
]


def menu():
    while True:
        idx = ui.menu("WEB", ITEMS)
        if idx is None: return
        ITEMS[idx][1]()
