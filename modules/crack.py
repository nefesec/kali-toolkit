"""Crack & hash : 4 actions — hashcat, john, crunch, hash-id."""

from core import ui, runner


def hashcat_run():
    ui.header("hashcat — dictionnaire")
    if not runner.check_tools(["hashcat"]): ui.pause(); return
    mode = ui.ask("mode (-m, ex: 0=MD5, 100=SHA1, 1000=NTLM, 22000=WPA)", default="0")
    hf   = ui.ask("fichier de hashes")
    wl   = ui.ask("wordlist", default="/usr/share/wordlists/rockyou.txt")
    if not hf: ui.pause(); return
    runner.run(["hashcat", "-m", mode, hf, wl], tag=f"hashcat-{mode}")
    ui.pause()


def john_run():
    ui.header("John the Ripper")
    if not runner.check_tools(["john"]): ui.pause(); return
    hf = ui.ask("fichier de hashes")
    wl = ui.ask("wordlist (vide=defaut)", default="")
    if not hf: ui.pause(); return
    args = ["john"]
    if wl: args += [f"--wordlist={wl}"]
    args.append(hf)
    runner.run(args, tag="john")
    ui.pause()


def crunch_gen():
    ui.header("crunch — générateur de wordlist")
    if not runner.check_tools(["crunch"]): ui.pause(); return
    mn  = ui.ask("min len", default="8")
    mx  = ui.ask("max len", default="8")
    chs = ui.ask("charset (vide = a-z0-9)", default="abcdefghijklmnopqrstuvwxyz0123456789")
    out = ui.ask("fichier sortie", default="wl.txt")
    runner.run(["crunch", mn, mx, chs, "-o", out], tag="crunch")
    ui.pause()


def hash_identify():
    ui.header("hash-identifier — type de hash")
    if not runner.check_tools(["hash-identifier"]): ui.pause(); return
    runner.run(["hash-identifier"], tag="hash-id")
    ui.pause()


ITEMS = [
    ("hashcat — dictionnaire",       hashcat_run),
    ("John the Ripper",              john_run),
    ("crunch — gen wordlist",        crunch_gen),
    ("hash-identifier",              hash_identify),
]


def menu():
    while True:
        idx = ui.menu("CRACK & HASH", ITEMS)
        if idx is None: return
        ITEMS[idx][1]()
