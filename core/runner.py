"""Wrapper subprocess avec logs + gestion Ctrl-C propre."""

import os
import subprocess
import shlex
import datetime
from . import ui

LOG_DIR = os.path.expanduser("~/.kt-logs")
os.makedirs(LOG_DIR, exist_ok=True)


def _log_path(tag):
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return os.path.join(LOG_DIR, f"{ts}-{tag}.log")


def run(cmd, tag="run", stream=True, root=False):
    """Lance une commande. cmd: str ou list. Retourne (code, log_path)."""
    if isinstance(cmd, str):
        display = cmd
        argv = shlex.split(cmd)
    else:
        display = " ".join(shlex.quote(a) for a in cmd)
        argv = cmd

    if root and os.geteuid() != 0:
        argv = ["sudo"] + argv
        display = "sudo " + display

    log_path = _log_path(tag)
    ui.info(f"cmd: {ui.D}{display}{ui.RESET}")
    ui.info(f"log: {ui.D}{log_path}{ui.RESET}\n")

    try:
        with open(log_path, "w") as logf:
            logf.write(f"# {datetime.datetime.now().isoformat()}\n# {display}\n\n")
            logf.flush()
            if stream:
                p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                try:
                    for line in p.stdout:
                        print(line, end="")
                        logf.write(line)
                except KeyboardInterrupt:
                    ui.warn("\ninterruption — arrêt du processus")
                    p.terminate()
                    try:
                        p.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        p.kill()
                code = p.wait()
            else:
                p = subprocess.run(argv, stdout=logf, stderr=subprocess.STDOUT, text=True)
                code = p.returncode
        return code, log_path
    except FileNotFoundError:
        ui.err(f"binaire introuvable : {argv[0]}")
        return 127, log_path


def need_tool(name):
    """Vérifie si un binaire existe dans le PATH."""
    return subprocess.call(["which", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def check_tools(tools):
    """Affiche les outils manquants. Retourne True si tous présents."""
    missing = [t for t in tools if not need_tool(t)]
    if missing:
        ui.err(f"outils manquants : {', '.join(missing)}")
        ui.info("installe via : sudo apt install " + " ".join(missing))
        return False
    return True
