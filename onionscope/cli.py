from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import APP_NAME, __version__
from .net import Cancelled, Net, detect_tor_port, tor_new_identity
from .modules import MODULES, BY_KEY
from .report import CYAN, DIM, MAGENTA, RESET, enable_ansi, format_text, log_line, make_entry, save_report

BANNER = r"""
   ____        _              ____
  / __ \____  (_)___  ____   / __/_________  ____  ___
 / / / / __ \/ / __ \/ __ \ _\ \/ ___/ __ \/ __ \/ _ \
/ /_/ / / / / / /_/ / / / //___/ /__/ /_/ / /_/ /  __/
\____/_/ /_/_/\____/_/ /_/    \___/\____/ .___/\___/
                                       /_/  OSINT · clearnet + Tor
"""

EXAMPLES = """przykłady:
  osint.py user torvalds
  osint.py domain example.com --subdomains -o raport.html
  osint.py --tor torcheck
  osint.py --tor search "bitcoin mixer" --engine ahmia --limit 20
  osint.py --tor crawl http://xxxxxxxx.onion --depth 2 --max-pages 40
  osint.py --tor onion adres1.onion adres2.onion
  osint.py ip 8.8.8.8 --json
  osint.py newnym                 (nowa tożsamość Tor)
  osint.py gui                    (interfejs graficzny)
"""


def _common() -> argparse.ArgumentParser:
    c = argparse.ArgumentParser(add_help=False)
    g = c.add_argument_group("sieć i wyjście")
    g.add_argument("--tor", action="store_true", default=argparse.SUPPRESS,
                   help="kieruj CAŁY ruch przez Tor (SOCKS5h, bez wycieków DNS)")
    g.add_argument("--tor-host", default=argparse.SUPPRESS, metavar="HOST", help="adres proxy Tor (domyślnie 127.0.0.1)")
    g.add_argument("--tor-port", type=int, default=argparse.SUPPRESS, metavar="PORT",
                   help="port SOCKS Tora (domyślnie autowykrycie 9050 / 9150)")
    g.add_argument("--timeout", type=float, default=argparse.SUPPRESS, metavar="S", help="limit czasu żądań [s]")
    g.add_argument("-o", "--output", default=argparse.SUPPRESS, metavar="PLIK",
                   help="zapisz raport do pliku .json lub .html")
    g.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="wypisz wynik jako JSON")
    g.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS, help="bez kolorów")
    return c


def build_parser() -> argparse.ArgumentParser:
    common = _common()
    p = argparse.ArgumentParser(
        prog="osint.py", parents=[common], formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{APP_NAME} {__version__} — narzędzie OSINT dla clearnetu i sieci Tor.", epilog=EXAMPLES)
    p.add_argument("-V", "--version", action="version", version=f"{APP_NAME} {__version__}")
    sub = p.add_subparsers(dest="cmd", metavar="KOMENDA", title="komendy")
    for m in MODULES:
        sp = sub.add_parser(m.key, parents=[common], help=m.title, description=m.description,
                            formatter_class=argparse.RawDescriptionHelpFormatter)
        if m.target:
            sp.add_argument("target", nargs="+" if m.multi else None, metavar=m.target.upper().replace(" ", "_"),
                            help=f"{m.target} (np. {m.example})")
        for o in m.opts:
            flag = "--" + o.name.replace("_", "-")
            if o.kind == "bool":
                sp.add_argument(flag, dest=o.name, action=argparse.BooleanOptionalAction, default=o.default,
                                help=o.help or o.label)
            elif o.kind == "int":
                sp.add_argument(flag, dest=o.name, type=int, default=o.default, metavar="N",
                                help=f"{o.label} (domyślnie {o.default})")
            else:
                sp.add_argument(flag, dest=o.name, choices=o.choices, default=o.default,
                                help=f"{o.label}{' — ' + o.help if o.help else ''}")
    nn = sub.add_parser("newnym", parents=[common], help="nowa tożsamość Tor (nowe obwody / IP wyjścia)")
    nn.add_argument("--control-port", type=int, default=0, help="port kontrolny (domyślnie 9051, potem 9151)")
    nn.add_argument("--password", default=None, help="hasło portu kontrolnego (HashedControlPassword)")
    sub.add_parser("gui", help="uruchom interfejs graficzny")
    return p


INTERACTIVE_HELP = """Wpisuj komendy tak jak w CLI, tylko bez „osint.py”, np.:
  user torvalds                 domain example.com --subdomains
  ip 8.8.8.8                    email kontakt@example.com
  search "tor project"          crawl https://example.com --depth 2
  onion <adres>.onion           -o raport.html domain example.com
Polecenia sesji:
  tor on / tor off   — tryb Tor dla kolejnych komend      torcheck — test połączenia
  help               — pełna pomoc   (help domain — pomoc modułu)
  gui                — okno graficzne     exit — wyjście
"""


def interactive() -> int:
    import shlex
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    m, r, c, d = (MAGENTA, RESET, CYAN, DIM) if color else ("", "", "", "")
    print(m + BANNER + r)
    print(INTERACTIVE_HELP)
    parser = build_parser()
    tor = False
    while True:
        prompt = f"{m}osint{r}{'[' + c + 'tor' + r + ']' if tor else ''}> "
        try:
            line = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        low = line.lower()
        if low in ("exit", "quit", "q", "wyjdz", "wyjdź", "koniec"):
            break
        if low in ("help", "pomoc", "?", "h"):
            parser.print_help()
            continue
        if low in ("tor on", "tor"):
            tor = True
            port = detect_tor_port()
            print(f"{d}[i] Tryb Tor WŁĄCZONY" + (f" (wykryto port {port})" if port else
                  " — UWAGA: nie wykryto Tora na 9050/9150, uruchom Tor Browser") + r)
            continue
        if low == "tor off":
            tor = False
            print(f"{d}[i] Tryb Tor wyłączony (clearnet){r}")
            continue
        if low in ("cls", "clear"):
            os.system("cls" if os.name == "nt" else "clear")
            continue
        try:
            argv = [a[1:-1] if len(a) >= 2 and a[0] == a[-1] and a[0] in "\"'" else a
                    for a in shlex.split(line, posix=False)]
        except ValueError as e:
            print(f"[!] {e}")
            continue
        if argv[0].lower() in ("help", "pomoc") and len(argv) > 1:
            argv = [argv[1], "--help"]
        if argv[0].lower() in ("osint", "osint.py", "python"):
            argv = [a for a in argv[1:] if a.lower() != "osint.py"]
        if tor and "--tor" not in argv and argv and argv[0] not in ("gui", "newnym"):
            argv = ["--tor"] + argv
        try:
            main(argv, _interactive=True)
        except SystemExit:
            pass
        except KeyboardInterrupt:
            print("\n[!] Przerwano.")
        print()
    return 0


def main(argv=None, _interactive: bool = False) -> int:
    enable_ansi()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if argv is None and len(sys.argv) == 1 and sys.stdin.isatty():
        return interactive()
    parser = build_parser()
    args = parser.parse_args(argv)
    color = not getattr(args, "no_color", False) and sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    ecolor = not getattr(args, "no_color", False) and sys.stderr.isatty()

    def log(msg: str):
        print(log_line(msg, ecolor), file=sys.stderr, flush=True)

    if not args.cmd:
        print((MAGENTA if color else "") + BANNER + (RESET if color else ""))
        parser.print_help()
        return 0
    if args.cmd == "gui":
        from .gui import main as gui_main
        return gui_main()

    host = getattr(args, "tor_host", "127.0.0.1")
    if args.cmd == "newnym":
        try:
            log("[+] " + tor_new_identity(host, args.control_port, args.password))
            return 0
        except Exception as e:
            log(f"[!] {e}")
            return 1

    m = BY_KEY[args.cmd]
    use_tor = getattr(args, "tor", False)
    port = getattr(args, "tor_port", 0)
    if use_tor and not port:
        port = detect_tor_port(host)
        if not port:
            log(f"[!] Nie wykryto Tora na {host}:9050 ani {host}:9150.")
            log("[i] Uruchom Tor Browser (port 9150) albo usługę tor (port 9050), lub podaj --tor-port.")
            return 2
    try:
        net = Net(use_tor=use_tor, tor_host=host, tor_port=port, timeout=getattr(args, "timeout", 25))
    except RuntimeError as e:
        log(f"[!] {e}")
        return 2

    target = getattr(args, "target", None)
    opts = {o.name: getattr(args, o.name) for o in m.opts}
    log(f"[i] {APP_NAME} · moduł: {m.title} · tryb: {net.mode}")
    t0 = time.time()
    try:
        data = m.func(net, target, log, **opts)
    except KeyboardInterrupt:
        net.stop_event.set()
        log("[!] Przerwano (Ctrl+C).")
        if _interactive:
            return 130
        sys.stdout.flush()
        os._exit(130)
    except Cancelled:
        log("[!] Przerwano.")
        return 130
    except Exception as e:
        log(f"[!] Błąd: {e}")
        return 1

    entry = make_entry(m.key, m.title, target, net.mode, data, time.time() - t0)
    if getattr(args, "json", False):
        print(json.dumps(entry, ensure_ascii=False, indent=2, default=str))
    else:
        bar = "─" * 60
        print(f"\n{CYAN if color else ''}{bar}{RESET if color else ''}")
        print(format_text(data, color))
        print(f"{DIM if color else ''}{bar}\nczas: {entry['trwanie_s']} s · tryb: {net.mode}{RESET if color else ''}")
    out = getattr(args, "output", None)
    if out:
        save_report([entry], out)
        log(f"[+] Zapisano raport: {os.path.abspath(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
